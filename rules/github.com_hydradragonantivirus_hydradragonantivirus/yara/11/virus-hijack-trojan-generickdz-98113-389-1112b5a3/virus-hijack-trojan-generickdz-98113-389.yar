rule Virus_Hijack_Trojan_GenericKDZ_98113_389 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_389.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30d3594c9d765d290606ce97c9352e918b05b5c131befe4a0499f6d3aaf235ba"

  strings:
    $s1 = "%-4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}