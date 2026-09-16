rule Virus_Hijack_Gen_Trojan_ShellObject_ACZ_aijlKSl_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ACZ@aijlKSl_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1cc58a4e9ab68488ad9b30c6754c1276ea24697f205f640eaa3f7e893d963c3e"

  strings:
    $s1 = "b9ff4>i@jAnn<FqHrIvvDNyPzQ~~LV" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}