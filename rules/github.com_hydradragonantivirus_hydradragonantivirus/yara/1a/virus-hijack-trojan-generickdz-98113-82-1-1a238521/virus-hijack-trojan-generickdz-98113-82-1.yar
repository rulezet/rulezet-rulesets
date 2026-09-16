rule Virus_Hijack_Trojan_GenericKDZ_98113_82_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_82_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72a09bbab48c95eafa94744e0c991385cb7671aef952b4a67c728f59d0d73f88"

  strings:
    $s1 = "f?skag" fullword ascii
    $s2 = "\")BArE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}