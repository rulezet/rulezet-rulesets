rule Virus_Hijack_Trojan_GenericKDZ_98113_39 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_39.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "597c77eb5d89c08399c552da9b40599b2591afc7e93a6aec73ff244b7a1c67c7"

  strings:
    $s1 = "G4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}