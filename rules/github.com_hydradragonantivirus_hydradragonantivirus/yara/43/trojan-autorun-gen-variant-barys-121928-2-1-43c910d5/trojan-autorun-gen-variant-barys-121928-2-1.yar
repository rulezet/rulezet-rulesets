rule Trojan_Autorun_Gen_Variant_Barys_121928_2_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Variant.Barys.121928_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "995234bb1638ea39f75552d3b39bec1897f0f769acd596e1cd95c8f0f4f3f21f"

  strings:
    $s1 = "@Sby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}