rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_554_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_554_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4916f99ef91d553ac718ddd3e296e014e2927e4f0252045c30b2c60edb14547"

  strings:
    $s1 = "?Software Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}