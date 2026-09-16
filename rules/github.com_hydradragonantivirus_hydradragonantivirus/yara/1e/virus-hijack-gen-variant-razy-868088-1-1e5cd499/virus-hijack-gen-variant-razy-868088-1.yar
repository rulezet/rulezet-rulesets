rule Virus_Hijack_Gen_Variant_Razy_868088_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Razy.868088_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5842f46558fad8ed2b6379c2d3f460598115bb99b65cf7a2b105a3779f3b97be"

  strings:
    $s1 = "Semielision" fullword wide
    $s2 = "Serpentinic" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}