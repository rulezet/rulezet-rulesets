rule Virus_Hijack_Trojan_GenericKDZ_74550_334_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_334_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "900739565eb6b0c15b13a6e7ae7877c88ea24709354050bfbe9c86550a4ce1b6"

  strings:
    $s1 = "U;sUrd" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}