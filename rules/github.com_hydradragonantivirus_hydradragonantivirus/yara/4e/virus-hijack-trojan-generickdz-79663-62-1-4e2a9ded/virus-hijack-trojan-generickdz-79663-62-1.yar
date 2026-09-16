rule Virus_Hijack_Trojan_GenericKDZ_79663_62_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_62_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55116218062e21b67561b4bf8a5ffb9fa4e917509e475a1eb1836a28cb2b8774"

  strings:
    $s1 = "O}woDE,$" fullword ascii
    $s2 = "BRab{C" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}