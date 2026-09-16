rule Virus_Danger_Gen_Trojan_ShellObject_fKX_aeBHSxm_3 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.fKX@aeBHSxm_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0be2368aeab6af0d57a0918a12af30bffa2b05efbdad9c97b3fb01d4e47a722"

  strings:
    $s1 = "MvIRE_OLSA_V120103_Def_V122304 Page 1 of 11 " fullword ascii
    $s2 = "xt{Lora" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}