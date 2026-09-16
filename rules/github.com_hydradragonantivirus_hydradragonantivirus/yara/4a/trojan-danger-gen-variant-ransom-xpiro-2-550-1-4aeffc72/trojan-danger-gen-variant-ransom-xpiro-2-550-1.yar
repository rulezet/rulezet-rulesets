rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_550_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_550_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a82ca99d4699bcffd5aba5f4bd3706af6a52e58b47b9c37a4f87829ba8185798"

  strings:
    $s1 = "bEnI$E" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}