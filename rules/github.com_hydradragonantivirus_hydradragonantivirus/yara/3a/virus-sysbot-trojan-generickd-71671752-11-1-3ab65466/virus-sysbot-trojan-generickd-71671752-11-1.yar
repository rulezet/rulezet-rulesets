rule Virus_Sysbot_Trojan_GenericKD_71671752_11_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.GenericKD.71671752_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1a158e6c815c123947b98d701e3315e3241e02708dc6335e585d71fe441967c"

  strings:
    $s1 = "DaRT]aK" fullword ascii
    $s2 = "!DiRT}MG" fullword ascii
    $s3 = "lurA)u" fullword ascii
    $s4 = "WHusH(" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}