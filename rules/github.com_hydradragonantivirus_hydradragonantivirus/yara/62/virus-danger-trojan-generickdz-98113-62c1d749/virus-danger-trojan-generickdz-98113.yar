rule Virus_Danger_Trojan_GenericKDZ_98113 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Trojan.GenericKDZ.98113.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59981d3fb47093e5d0fd410930e5189ad8e341261f487fc972dff8a6cce01ad8"

  strings:
    $s1 = "e(4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}