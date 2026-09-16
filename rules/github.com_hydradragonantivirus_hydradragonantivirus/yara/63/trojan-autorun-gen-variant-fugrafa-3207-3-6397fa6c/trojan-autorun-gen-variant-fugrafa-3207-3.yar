rule Trojan_Autorun_Gen_Variant_Fugrafa_3207_3 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Variant.Fugrafa.3207_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c7bae36ab10d5855b4c98ae1cd157d8c3223d291b64ab86a18b078febfa69a1"

  strings:
    $s1 = "lby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}