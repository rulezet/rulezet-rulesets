rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_14_68 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.14_68.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3cbaf28e2d6676e48ca8fcd0738f82f20cc6940082c3c6051a9b62087c42c8e"

  strings:
    $s1 = "oUTfiT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}