rule Virus_Hijack_Trojan_GenericKDZ_105930_29_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105930_29_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37de214e05d29ce5c2200aea036edd1d4d8fe3aeffad15de2c0135b236d65950"

  strings:
    $s1 = "*CU^)KInk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}