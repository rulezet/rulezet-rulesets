rule Virus_Sysbot_Trojan_GenericKD_71671752_23_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.GenericKD.71671752_23_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1fc2b8edf9fab7077e8ad3a38a5852d2d8e62c91f244cad27eb23063f7e293e"

  strings:
    $s1 = "ryOt#T" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}