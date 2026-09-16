rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_148_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_148_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce4da06f7799160ba280ff31012e7a16ec8948c1b5327d9a4be2d9d20fd5f0ca"

  strings:
    $s1 = "*Vare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}