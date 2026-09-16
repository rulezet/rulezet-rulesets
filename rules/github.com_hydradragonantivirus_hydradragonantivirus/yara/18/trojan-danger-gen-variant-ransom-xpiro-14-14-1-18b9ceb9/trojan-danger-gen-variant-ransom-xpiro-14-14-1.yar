rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_14_14_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.14_14_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "911a96a61d26650cda29db23ce1b62d429096544a1c6cef5396e0dd5fb16c85a"

  strings:
    $s1 = "wthat party must agree that this agreement applies to the transfer and use of the software. You may not" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}