rule Virus_Hijack_Gen_Variant_Doina_58391_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Doina.58391_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5ebe7df6c60c6f50a5253a2eb5d82f5a4b5d34ca271dfc8e212ea398ae61d07"

  strings:
    $s1 = "Dark EyE Coders" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}