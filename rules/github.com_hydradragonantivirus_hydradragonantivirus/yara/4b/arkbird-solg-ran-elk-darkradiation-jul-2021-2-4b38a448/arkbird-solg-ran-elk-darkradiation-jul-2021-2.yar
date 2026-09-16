rule ARKBIRD_SOLG_RAN_ELK_Darkradiation_Jul_2021_2: FILE {
  meta:
    description = "Detect the DarkRadiation ransomware"
    author      = "Arkbird_SOLG"
    id          = "3580a41a-ba2e-5a47-b35d-b2482fbc913a"
    date        = "2021-07-03"
    modified    = "2021-07-05"
    reference   = "https://bazaar.abuse.ch/browse/tag/DarkRadiation/"
    source_url  = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-07-04/DarkRadiation/RAN_ELK_DarkRadiation_Jul_2021_2.yara#L1-L27"
    license_url = "N/A"
    logic_hash  = "b21db1658845cafe37950d69b5bc0aab203e7bea3e43f95394236e0133234e2d"
    score       = 75
    quality     = 57
    tags        = "FILE"
    hash1       = "3bab2947305c00df66cb4d6aaef006f10aca348c17aa2fd28e53363a08b7ec68"
    hash2       = "652ee7b470c393c1de1dfdcd8cb834ff0dd23c93646739f1f475f71a6c138edd"
    hash3       = "79aee7a4459d49dc6dfebf1a45d32ccc3769a1e5c1f231777ced3769607ba9c1"
    tlp         = "White"
    adversary   = "FERRUM"

  strings:
    $s1  = "allThreads=($1)"
    $s2  = "MSG_URL='https://api.telegram.org/bot'$TOKEN'/sendMessage?chat_id='"
    $s3  = "if [[ \"$master\" != \"$slave\" ]]"
    $s4  = "user_host=$(echo \"${parse_arg}\" | awk -F \"|\" '{print $1}')"
    $s5  = "master=$(cat /tmp/.ccw | wc -l)"
    $s6  = "send_message $id \"$(hostname) $(hostname -I)"
    $s7  = "start_thread $allThreads"
    $s8  = "ip_host=$(echo \"${parse_arg}\" | awk -F \"|\" '{print $2}')"
    $s9  = "port_host=$(echo \"${parse_arg}\" | awk -F \"|\" '{print $3}')"
    $s10 = { 24 28 63 75 72 6c 20 2d 73 20 2d 2d 69 6e 73 65 63 75 72 65 20 2d 2d 64 61 74 61 2d 75 72 6c 65 6e 63 6f 64 65 20 22 74 65 78 74 3d [2-15] 22 20 22 24 4d 53 47 5f 55 52 4c [2-15] 22 20 26 29 }
    $s11 = { 73 6c 61 76 65 3d 24 28 65 63 68 6f 20 22 24 7b [2-15] 7d 22 20 7c 20 77 63 20 2d 6c 29 }

  condition:
    filesize > 1KB and 6 of ($s*)
}