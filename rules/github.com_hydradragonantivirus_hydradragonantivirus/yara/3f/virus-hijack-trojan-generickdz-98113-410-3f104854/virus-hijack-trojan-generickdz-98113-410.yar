rule Virus_Hijack_Trojan_GenericKDZ_98113_410 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_410.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee233486ddc4efb795bc2139fc8c5a3379a0dbff75e38815e6a75bd90b7ea558"

  strings:
    $s1 = "_4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}