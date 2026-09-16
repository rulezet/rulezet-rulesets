rule Virus_Hijack_Trojan_GenericKDZ_98113_193 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_193.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86b6d6b8b77c606a001195386128d2461b7b61243880067ce89affc24308f8d3"

  strings:
    $s1 = "04. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}