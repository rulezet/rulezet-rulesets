rule Virus_Sysbot_Trojan_GenericKD_71671752_10_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.GenericKD.71671752_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e48ff7b6cd8844e3a309b278ad8b830d2e0afc3d9e703cbc3672216886d5c728"

  strings:
    $s1 = "@SuCh!]" fullword ascii
    $s2 = "visE$6d" fullword ascii
    $s3 = "PeTe`^" fullword ascii
    $s4 = "meTe`Q" fullword ascii
    $s5 = "@T(menu" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}