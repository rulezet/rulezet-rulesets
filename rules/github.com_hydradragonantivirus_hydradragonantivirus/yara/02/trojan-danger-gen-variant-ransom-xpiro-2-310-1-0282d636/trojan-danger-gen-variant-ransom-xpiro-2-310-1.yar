rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_310_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_310_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55bccdc9bf566a3eff1511b9e010614c6ff7ea2cb9124b1574cca315debe0a7c"

  strings:
    $s1 = "NAsoftware features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}