rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_406_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_406_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c7b128a054cbcab650d06901c259f320e5e510d151eaa3343fc04ce4f26bde6f"

  strings:
    $s1 = "Cand services at the list price in effect at the " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}