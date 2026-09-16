rule Virus_Hijack_Trojan_Peed_Gen_22_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_22_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ef2d5acd8cd8ff4c3ea2ee2c65c35752071b1326726b8d3d7c983320fe6bd22"

  strings:
    $s1 = "torc;9'" fullword ascii
    $s2 = "FAff(sT" fullword ascii
    $s3 = "frOe{Si" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}