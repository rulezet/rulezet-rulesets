rule Virus_Hijack_Gen_Variant_Razy_104452 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Razy.104452.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "45955fb4e8a2e62bbd8f21a7914fe2dd7259c95e14732fe4e97bf1c9c609ecdb"

  strings:
    $s1 = "jointuress" fullword wide
    $s2 = "wheelrace" fullword wide
    $s3 = "griffonage" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}