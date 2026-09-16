rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_496 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_496.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18f01d34c46ecd20ca47f2d861a9a79cf7e443ab6ad66ab732b443b224135c11"

  strings:
    $s1 = "Compile Script to .exe (x64).lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}