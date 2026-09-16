rule Virus_Hijack_Gen_Variant_Razy_104452_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Razy.104452_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40152914e7456e723a293b9d1173b6fb92ca3d1a6e6faf421bed8c0935a524f1"

  strings:
    $s1 = "jointuress" fullword wide
    $s2 = "wheelrace" fullword wide
    $s3 = "griffonage" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}