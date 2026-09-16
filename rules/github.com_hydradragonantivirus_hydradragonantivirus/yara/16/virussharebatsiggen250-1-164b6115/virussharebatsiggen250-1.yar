rule VirusShareBATSiggen250_1 {
  meta:
    description = "datamaliciousorder - file VirusShareBATSiggen250_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "04db5a7b6dba315b36c7ec7de274e55972fd3d49b3d7d6793b259a176aaf4bfe"

  strings:
    $s1  = "**Operating System:** `` " fullword wide
    $s2  = "**System Name:** `` " fullword wide
    $s3  = "**Token:** `` " fullword wide
    $s4  = "Mozilla/5.0 AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11" fullword wide
    $s5  = "**Internet Provider:** `` " fullword wide
    $s6  = "**Phone Number:** `` " fullword wide
    $s7  = " ***Computer Information***" fullword wide
    $s8  = "**Locale:** `` " fullword wide
    $s9  = "Copyright 1969" fullword wide
    $s10 = "**FALSE**" fullword wide
    $s11 = "Nuke Grabber" fullword wide
    $s12 = "**Location:** `` " fullword wide
    $s13 = "***Discord Information***" fullword wide
    $s14 = "**Profile Picture:**" fullword wide
    $s15 = "Nuke Grabber created by Adolf Hitler" fullword wide
    $s16 = "Wallpaper Motor" fullword wide
    $s17 = "PASTE YOUR OWN WEBHOOK URI HERE" fullword wide
    $s18 = "Invalid Webhook URL." fullword wide
    $s19 = "**TRUE**" fullword wide
    $s20 = "***Location Based Information***" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}