rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_33_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_33_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cbd4a13350a0d7c3bfec183a2c79fbf2882f0e23009ffb9a1b132e88ed72bf9c"

  strings:
    $s1 = "L`virtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}