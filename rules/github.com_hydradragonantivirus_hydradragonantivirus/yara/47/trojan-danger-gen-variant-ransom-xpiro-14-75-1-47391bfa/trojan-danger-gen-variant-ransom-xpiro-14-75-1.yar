rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_14_75_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.14_75_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21e5927e2e02d129e13965329d7169b3ba21eb1d687962c9552a5f39814c59e2"

  strings:
    $s1 = "\"tINt#" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}