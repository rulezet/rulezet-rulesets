rule Virus_Hijack_Trojan_GenericKDZ_98113_208 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_208.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7b885b0ad16581e8f182609afa642f9d47ba39b56864f17d2fe1b510fce602f"

  strings:
    $s1 = "wT4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}