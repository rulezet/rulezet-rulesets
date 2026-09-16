rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_62_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_62_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d1467578ce99ba60e8998d87adac6924d80f4bcd60c26ecda1816740e42de81"

  strings:
    $s1 = "2University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}