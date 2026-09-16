rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_195_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_195_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "245d6ca0e19b943a5bd8aa33d30d8afce64d7bed12b0ecd48cf9e9df40dec397"

  strings:
    $s1 = "drivEn" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}