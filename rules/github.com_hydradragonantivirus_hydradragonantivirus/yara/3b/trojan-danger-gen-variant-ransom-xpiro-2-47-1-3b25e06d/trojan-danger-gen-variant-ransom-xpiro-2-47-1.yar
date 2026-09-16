rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_47_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_47_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "83d13d46bf41b6b75d83a6c4db00a6a92e3257a13615dbf9e93bf426068fbb07"

  strings:
    $s1 = "\"Fpurposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}