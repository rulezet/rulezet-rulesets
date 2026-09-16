rule Virus_Sysbot_Trojan_GenericKD_71671752_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.GenericKD.71671752_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8c2d13c773462493b788554cc0dffb3463707dee0d4684e5bece3177d5bc457"

  strings:
    $s1 = "Select windows" fullword wide
    $s2 = "Win Mixer" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}