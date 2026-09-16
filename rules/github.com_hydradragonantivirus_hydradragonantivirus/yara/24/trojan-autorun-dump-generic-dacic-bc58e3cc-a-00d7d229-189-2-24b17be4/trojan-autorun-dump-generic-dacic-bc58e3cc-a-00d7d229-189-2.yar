rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_189_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_189_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6cdb6651290591cfb555e80e0519098ffae63beeb7ab2890325f74048ae4357"

  strings:
    $s1 = "Boo.Lang.Builtins+<range>c__Iterator3" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}