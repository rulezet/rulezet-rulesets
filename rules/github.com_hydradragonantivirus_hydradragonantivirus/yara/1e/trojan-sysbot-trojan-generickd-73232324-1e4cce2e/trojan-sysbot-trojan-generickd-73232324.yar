rule Trojan_Sysbot_Trojan_GenericKD_73232324 {
  meta:
    description = "datamaliciousorder - file Trojan.Sysbot_Trojan.GenericKD.73232324.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41491f91cb513298101664097cc0cbe4bd13e9f889a4059778a31265a22b49e8"

  strings:
    $s1 = "BAUD:u,h" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}