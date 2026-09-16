rule Virus_Hijack_Gen_Trojan_ShellObject_yyZ_aSgChKg {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.yyZ@aSgChKg.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53e399cced84d5abb5552151e75fb80fccfa8ca0612602d135c5f1c23300831c"

  strings:
    $s1 = "_debug': False, " fullword ascii
    $s2 = "e, 'x_seq': None, 'f_seq': None,0" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}