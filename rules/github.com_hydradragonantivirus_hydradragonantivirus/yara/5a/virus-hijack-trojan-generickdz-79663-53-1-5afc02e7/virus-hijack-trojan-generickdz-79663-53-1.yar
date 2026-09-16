rule Virus_Hijack_Trojan_GenericKDZ_79663_53_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_53_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f5761d9a581f5e7df758fe340e7f66776f1cb20e1cb03cc901eaabfad414309"

  strings:
    $s1 = "=#BLAN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}