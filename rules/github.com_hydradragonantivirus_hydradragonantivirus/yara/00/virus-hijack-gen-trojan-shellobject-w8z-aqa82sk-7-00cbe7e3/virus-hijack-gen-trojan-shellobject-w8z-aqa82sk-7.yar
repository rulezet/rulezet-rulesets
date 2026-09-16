rule Virus_Hijack_Gen_Trojan_ShellObject_w8Z_aqA82Sk_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.w8Z@aqA82Sk_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "384b731f758c792b47f2b45175a54e7f88c4423bff013e56819bce6d0bdc92e6"

  strings:
    $s1 = "\"pIRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}