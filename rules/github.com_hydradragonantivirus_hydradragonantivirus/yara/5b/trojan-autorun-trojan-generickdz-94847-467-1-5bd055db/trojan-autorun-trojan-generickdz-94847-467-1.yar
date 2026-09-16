rule Trojan_Autorun_Trojan_GenericKDZ_94847_467_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_467_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43d525ed7129e1bf6103768040c34bf1b63e4a8548ca9098b7d92892e8e402d5"

  strings:
    $s1 = "AIRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}