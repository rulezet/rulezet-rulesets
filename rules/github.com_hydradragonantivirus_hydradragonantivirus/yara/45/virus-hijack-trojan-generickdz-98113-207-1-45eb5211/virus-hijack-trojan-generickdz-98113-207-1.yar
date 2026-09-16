rule Virus_Hijack_Trojan_GenericKDZ_98113_207_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_207_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "25c29d03344c250bd96407c042a3fced031f94bd850624bbc2bb1ff7a5908031"

  strings:
    $s1 = "\"N](EBOe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}