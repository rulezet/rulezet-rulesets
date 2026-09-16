rule Trojan_Autorun_Gen_Variant_Barys_95064_28_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Variant.Barys.95064_28_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fda3b9b83d515db24187856d78d87e88556b192d413f8964e6fd6530fd022f2c"

  strings:
    $s1 = "dhundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}