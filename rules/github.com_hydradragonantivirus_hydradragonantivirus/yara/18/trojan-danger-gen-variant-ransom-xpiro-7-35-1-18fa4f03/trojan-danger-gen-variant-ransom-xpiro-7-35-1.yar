rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_35_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_35_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81a95a720e45b9baf8d5f78abc861867f4765fc09925b6614e9148a7cc563e39"

  strings:
    $s1 = "=a neutral arbitrator, whose decision will be final except for a limited right of appeal under the Federal" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}