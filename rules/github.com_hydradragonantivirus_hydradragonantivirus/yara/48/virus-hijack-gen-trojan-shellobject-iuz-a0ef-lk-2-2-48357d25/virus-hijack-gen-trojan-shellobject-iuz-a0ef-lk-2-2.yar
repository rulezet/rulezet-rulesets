rule Virus_Hijack_Gen_Trojan_ShellObject_iuZ_a0EF_lk_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.iuZ@a0EF!lk_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b83dc72e6e582a33f79ad645f15a513d871a975b3d31a6add7fa171e05aaee76"

  strings:
    $s1 = "Rich*/" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}