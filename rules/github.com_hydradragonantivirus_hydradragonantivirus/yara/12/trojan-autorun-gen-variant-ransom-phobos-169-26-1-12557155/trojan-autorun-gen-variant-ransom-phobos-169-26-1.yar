rule Trojan_Autorun_Gen_Variant_Ransom_Phobos_169_26_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Variant.Ransom.Phobos.169_26_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "353fca0bb63be72d226111ac435d2cafea8f11d1196ac5215b2d174be158d7e9"

  strings:
    $s1 = "g,by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}