rule Trojan_Autorun_Trojan_Generic_7761207_2_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.Generic.7761207_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26bc9b37da6d281d1a16b63cc46a9284c5ed1106fa2fc5ad5d7c7667378eb87a"

  strings:
    $s1 = "H2functionality of the programs. You have 30 days " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}