rule Virus_Danger_Gen_Trojan_ShellObject_fKX_aeBHSxm_2 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.fKX@aeBHSxm_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fcdb6eba6c9cc13908e3da9575a9473c5b3e98a0f5ff76dd859d7c48201ccf08"

  strings:
    $s1 = "YiIRE_OLSA_V120103_Def_V122304 Page 1 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}