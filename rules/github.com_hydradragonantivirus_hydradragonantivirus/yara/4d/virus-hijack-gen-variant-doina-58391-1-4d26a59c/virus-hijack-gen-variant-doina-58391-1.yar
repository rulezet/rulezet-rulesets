rule Virus_Hijack_Gen_Variant_Doina_58391_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Doina.58391_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e12a478c0da5b8cf7a9b49060655ad4028f116080dfddbdac9e9f4a527840bcc"

  strings:
    $s1 = "Dark EyE Coders" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}