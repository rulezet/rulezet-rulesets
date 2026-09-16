rule Virus_Hijack_Gen_Variant_Packy_4_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Packy.4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e11f0c44cc4e55337b70e290409fd2e7468f4b6986e4b26948934945461fee2"

  strings:
    $s1 = "akinesia" fullword wide
    $s2 = "Roundwood" fullword wide
    $s3 = "Grison" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}