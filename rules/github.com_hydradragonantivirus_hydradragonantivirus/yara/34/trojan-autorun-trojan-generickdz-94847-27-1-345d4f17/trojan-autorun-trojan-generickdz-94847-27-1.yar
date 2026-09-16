rule Trojan_Autorun_Trojan_GenericKDZ_94847_27_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_27_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "caca03504e003304ca7f30e79b60c43e40855050c528f119a3d81df9ca4ff1dd"

  strings:
    $s1 = "VPIRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}