rule Virus_Hijack_Gen_Variant_Zbot_40_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Zbot.40_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3403266e4adfe073a915d16a0bb9feb776f2c713453b61a26d09f6314165fd6"

  strings:
    $s1 = "shatterheaded" fullword wide
    $s2 = "loiterer" fullword wide
    $s3 = "Daintiness" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}