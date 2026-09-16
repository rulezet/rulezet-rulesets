rule ARKBIRD_SOLG_RAN_ELK_Darkradiation_Jul_2021_1: FILE {
  meta:
    description = "Detect the DarkRadiation ransomware"
    author      = "Arkbird_SOLG"
    id          = "13d77ecc-14ab-54ce-9eec-2d614f5ae8e4"
    date        = "2021-07-03"
    modified    = "2021-07-05"
    reference   = "https://bazaar.abuse.ch/browse/tag/DarkRadiation/"
    source_url  = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-07-04/DarkRadiation/RAN_ELK_DarkRadiation_Jul_2021_1.yara#L1-L25"
    license_url = "N/A"
    logic_hash  = "6fbc6eed7dd7f92af0cd8b3b2726636a64dc8de0b795b176169817994f44d4fa"
    score       = 75
    quality     = 61
    tags        = "FILE"
    hash1       = "1c2b09417c1a34bbbcb8366c2c184cf31353acda0180c92f99828554abf65823"
    hash2       = "d0d3743384e400568587d1bd4b768f7555cc13ad163f5b0c3ed66fdc2d29b810"
    hash3       = "e380c4b48cec730db1e32cc6a5bea752549bf0b1fb5e7d4a20776ef4f39a8842"
    tlp         = "White"
    adversary   = "FERRUM"

  strings:
    $s1 = "PASS_DEC=$(openssl enc -base64 -aes-256-cbc -d -pass pass:$PASS_DE <<< $1)"
    $s2 = "rm -rf $PATH_TEMP_FILE/$NAME_SCRIPT_CRYPT"
    $s3 = { 74 65 6c 65 67 72 61 6d 5f 62 6f 74 2f [5-15] 2d 6f 20 22 2f }
    $s4 = "-o \"/tmp/bash.sh\";cd /tmp;chmod +x bash.sh;./bash.sh;"
    $s5 = "xargs -P 10 -I FILE openssl enc -aes-256-cbc -salt -pass pass"
    $s6 = "xargs -P 10 -I FILE openssl enc -aes-256-cbc -salt -pass pass:$PASS_DEC -in FILE -out FILE."
    $s7 = "usermod --shell /bin/nologin"
    $s8 = { 67 72 65 70 20 2d 46 20 22 24 22 20 2f 65 74 63 2f 73 68 61 64 6f 77 20 7c 20 63 75 74 20 2d 64 3a 20 2d 66 31 20 7c 20 67 72 65 70 20 2d 76 20 22 [1-15] 22 20 7c 20 78 61 72 67 73 20 2d 49 20 46 49 4c 45 20 67 70 61 73 73 77 64 20 2d 64 20 46 49 4c 45 20 77 68 65 65 6c }
    $s9 = "systemctl stop docker && systemctl disable docker"

  condition:
    filesize > 5KB and 5 of ($s*)
}