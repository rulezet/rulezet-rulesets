rule Trojan_Autorun_Gen_Variant_Fragtor_592580_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Variant.Fragtor.592580_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "445869027d71c833d4d271a2486be7c9e0e8feb6089ae8b752698f4b1e69f843"

  strings:
    $s1 = "Mvby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}