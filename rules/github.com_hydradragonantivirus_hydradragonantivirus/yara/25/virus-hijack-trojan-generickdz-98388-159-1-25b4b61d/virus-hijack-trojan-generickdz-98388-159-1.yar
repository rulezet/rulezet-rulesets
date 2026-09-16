rule Virus_Hijack_Trojan_GenericKDZ_98388_159_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_159_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1bbc66f0790bab2e72b06ae7c1e537af86cc668c48cea87cd78e2c3afea3f44"

  strings:
    $s1 = "JINk<q" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}