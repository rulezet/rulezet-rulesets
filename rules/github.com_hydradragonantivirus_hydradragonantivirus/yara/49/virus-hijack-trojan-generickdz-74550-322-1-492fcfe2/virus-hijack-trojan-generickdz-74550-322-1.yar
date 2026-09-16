rule Virus_Hijack_Trojan_GenericKDZ_74550_322_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_322_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cdf7b5fa14e3549a02f890e886f56b9619495a7735410fff9dc7923d86964bff"

  strings:
    $s1 = "EggY;g" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}