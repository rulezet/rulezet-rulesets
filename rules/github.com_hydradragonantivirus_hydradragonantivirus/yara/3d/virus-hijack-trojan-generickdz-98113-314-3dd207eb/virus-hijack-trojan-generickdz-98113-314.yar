rule Virus_Hijack_Trojan_GenericKDZ_98113_314 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_314.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dac44e57231cc798b25f51ddda84ffb98c1d16c18712cea28b718649490c0716"

  strings:
    $s1 = "s4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}