rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_536_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_536_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2853caadd27aeb1c8e82ead5ec47c9c55fa68b4a06dab367e7dae7edf31025ad"

  strings:
    $s1 = "2University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}