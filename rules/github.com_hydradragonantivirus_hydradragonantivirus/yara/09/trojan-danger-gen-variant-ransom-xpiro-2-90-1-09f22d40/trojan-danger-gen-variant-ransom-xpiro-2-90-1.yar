rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_90_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_90_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65a283ea2da2b9f46e63cf3f76f79828fa876fd5449aaeedf20d0a6c1af7005e"

  strings:
    $s1 = "and/or running. With respect to the Customer Data Hub program, in determining the number " fullword ascii
    $s2 = "-must be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}