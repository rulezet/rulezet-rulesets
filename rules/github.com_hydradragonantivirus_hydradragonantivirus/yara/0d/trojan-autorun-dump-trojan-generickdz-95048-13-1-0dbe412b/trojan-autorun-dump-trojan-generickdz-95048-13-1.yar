rule Trojan_Autorun_Dump_Trojan_GenericKDZ_95048_13_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Trojan.GenericKDZ.95048_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ed4ab758125f134e2ffcdee7e81bf747e328665a9f9ed994d81a90479fc9cc7"

  strings:
    $s1 = "+and hardware systems to the applications programs and (c) building extensions to applications programs. You shall not" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}