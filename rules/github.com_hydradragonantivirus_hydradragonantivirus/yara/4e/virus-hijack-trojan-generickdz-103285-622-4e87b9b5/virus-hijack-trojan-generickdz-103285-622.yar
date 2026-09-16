rule Virus_Hijack_Trojan_GenericKDZ_103285_622 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_622.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a9faedec97be1a219fcdf37376ea29cb5681b5d69ee9dcb4379a383d7b9f6a0"

  strings:
    $s1 = ":RUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}