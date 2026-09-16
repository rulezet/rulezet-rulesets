rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_14_61_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.14_61_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d34fe092fd7ece92ac83f6d01064bc04476db4c25f98fd50a9801da88774240"

  strings:
    $s1 = "\"}WZf`yIrd" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}