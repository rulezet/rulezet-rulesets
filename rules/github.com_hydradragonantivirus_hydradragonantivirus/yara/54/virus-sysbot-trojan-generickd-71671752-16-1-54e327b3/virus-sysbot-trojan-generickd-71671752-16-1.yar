rule Virus_Sysbot_Trojan_GenericKD_71671752_16_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.GenericKD.71671752_16_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3786581341caf5604b7ec5f6104f7c7c0555626a318fcd4537a83204609a0fe3"

  strings:
    $s1 = "Jama!-" fullword ascii
    $s2 = "#%dePA" fullword ascii
    $s3 = "R`hAdj'" fullword ascii
    $s4 = "<TRYp]" fullword ascii
    $s5 = "bRAb}p" fullword ascii
    $s6 = "pIanT}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}