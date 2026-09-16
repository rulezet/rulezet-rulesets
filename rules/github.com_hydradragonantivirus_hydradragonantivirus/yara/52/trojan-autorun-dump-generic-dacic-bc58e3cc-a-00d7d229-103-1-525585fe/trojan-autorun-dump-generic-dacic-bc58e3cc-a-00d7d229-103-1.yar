rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_103_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_103_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6cdf26b866307638be337d103f3ed9dfc52e7724945a2b05f4af9f6e606a39e"

  strings:
    $s1 = "s policies regarding financing which " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}