rule Virus_Hijack_Gen_Variant_Packy_4_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Packy.4_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac04eac7277d8a07afadc074068c605693c81b79c017d1fa902ad2b619039335"

  strings:
    $s1 = "akinesia" fullword wide
    $s2 = "Roundwood" fullword wide
    $s3 = "Grison" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}