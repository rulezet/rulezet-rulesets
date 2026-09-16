rule Virus_Hijack_Trojan_GenericKDZ_98113_303 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_303.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "66721d1db9618b90b3b4f61e5ffe6542a8e3e84c5219bac85dae19c16b703a49"

  strings:
    $s1 = "14. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}