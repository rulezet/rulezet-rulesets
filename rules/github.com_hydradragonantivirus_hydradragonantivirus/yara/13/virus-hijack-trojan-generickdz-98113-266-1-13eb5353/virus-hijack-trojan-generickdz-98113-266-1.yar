rule Virus_Hijack_Trojan_GenericKDZ_98113_266_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_266_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f22f2049d5277908d5eb1f45332cb7d39d1e1aada52b6e8e5b33cc0180e420a9"

  strings:
    $s1 = "Mw;eUGe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}