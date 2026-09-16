rule Virus_Hijack_Gen_Variant_Doina_58391_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Doina.58391_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae95c0813acb407c6131600ce3f73b5d7653efa29a69c000326963b3255671a6"

  strings:
    $s1 = "Dark EyE Coders" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}