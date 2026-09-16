rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_303_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_303_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88c11802a7fc9de2770cdb2e049b4ca25a23c47ed0a0046ea8477163e73fe70f"

  strings:
    $s1 = "^software features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}