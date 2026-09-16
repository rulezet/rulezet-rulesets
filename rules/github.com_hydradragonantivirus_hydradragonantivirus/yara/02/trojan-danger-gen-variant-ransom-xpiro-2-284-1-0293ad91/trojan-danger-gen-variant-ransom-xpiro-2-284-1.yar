rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_284_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_284_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dadc79f57e89d942594be17670ef5dda98ca2d65d9f01f88c22605cee8105c26"

  strings:
    $s1 = "M/Professional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}