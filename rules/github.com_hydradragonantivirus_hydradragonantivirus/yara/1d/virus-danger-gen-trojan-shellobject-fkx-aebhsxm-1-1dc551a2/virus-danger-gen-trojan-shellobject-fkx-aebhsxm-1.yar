rule Virus_Danger_Gen_Trojan_ShellObject_fKX_aeBHSxm_1 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.fKX@aeBHSxm_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e062de4d8384e809cb6540ab2b8de0665e6b3a36c14f09d0846259c4e013a808"

  strings:
    $s1 = "@AIRE_OLSA_V120103_Def_V122304 Page 1 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}