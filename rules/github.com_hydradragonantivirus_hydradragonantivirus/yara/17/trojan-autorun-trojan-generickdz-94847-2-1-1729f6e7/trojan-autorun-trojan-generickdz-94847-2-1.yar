rule Trojan_Autorun_Trojan_GenericKDZ_94847_2_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8884f2e9b931ce7fb90cda2b1911f90dc2c2757583b63fd474421bcf718b867d"

  strings:
    $s1 = "2orders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}