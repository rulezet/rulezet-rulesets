rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_456_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_456_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "04e277bcf5e62d6881f504e65e607bc72c631d5ffb987dfdaf4077dcb629a675"

  strings:
    $s1 = " Setup\\InstalAd Component<" fullword ascii
    $s2 = "r\\Shell Fold" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}