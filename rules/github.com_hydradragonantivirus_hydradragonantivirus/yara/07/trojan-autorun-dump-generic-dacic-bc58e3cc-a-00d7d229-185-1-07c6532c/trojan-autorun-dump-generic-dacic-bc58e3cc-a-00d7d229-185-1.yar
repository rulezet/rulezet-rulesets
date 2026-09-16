rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_185_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_185_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "556e1615e476db6419e14094c3aace7168e994b3865b06d7906092389e0963a6"

  strings:
    $s1 = "s policies regarding financing which " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}