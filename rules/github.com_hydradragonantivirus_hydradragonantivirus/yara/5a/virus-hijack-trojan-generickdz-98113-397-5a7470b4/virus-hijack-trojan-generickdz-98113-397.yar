rule Virus_Hijack_Trojan_GenericKDZ_98113_397 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_397.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c8b380bb620b2b414e49d510629b70023001c917d0c493b4abf62e39df58247"

  strings:
    $s1 = "R4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}