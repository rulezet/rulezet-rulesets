rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_135_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_135_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c21f8b253e9db8a5efb810d8cc1d6d6de493a457adc1568b130906901c9d0b8"

  strings:
    $s1 = "a9Oracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}