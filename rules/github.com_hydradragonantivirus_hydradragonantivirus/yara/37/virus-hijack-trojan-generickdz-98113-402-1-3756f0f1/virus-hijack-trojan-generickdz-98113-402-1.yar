rule Virus_Hijack_Trojan_GenericKDZ_98113_402_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_402_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5bd616c39b46c4776209bac1c03b1551bb67fd0299ef05c3c1d9495ab3458971"

  strings:
    $s1 = "sNAB!?O" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}