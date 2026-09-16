rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_64_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_64_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2bf7a0a25eaf651a1f7192d83142ff625ab6daecf9ae26ff13dd68bde83a8813"

  strings:
    $s1 = ":Software Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}