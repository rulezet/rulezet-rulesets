rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_243_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_243_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e03ddc574899186abfc5099eb671a6c4acd15cdb3d2a360b7f78df7b96ecbd9"

  strings:
    $s1 = "HIRe$&1>&VC" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}