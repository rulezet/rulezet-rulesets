rule Trojan_Autorun_Gen_Variant_Barys_121928_14_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Variant.Barys.121928_14_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1718aa199a78dec9c5eb424804b630d13bb23a075a00c2f64e8641abc540fe87"

  strings:
    $s1 = "#by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}