rule Virus_Hijack_Gen_Trojan_ShellObject_yyZ_aSgChKg_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.yyZ@aSgChKg_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b8e651eb2afb44d46640272efd1f816fee5db62fc21d83d9c1b07c32e4a74de7"

  strings:
    $s1 = "_debug': False, " fullword ascii
    $s2 = "e, 'x_seq': None, 'f_seq': None,0" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}