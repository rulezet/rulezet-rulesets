rule Virus_Hijack_Trojan_GenericKDZ_98113_33 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_33.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e40268d2e2874438f910acbc3ebbe3dc760bc2945a714a35e2d4fc6cab9b647"

  strings:
    $s1 = "Uhundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}