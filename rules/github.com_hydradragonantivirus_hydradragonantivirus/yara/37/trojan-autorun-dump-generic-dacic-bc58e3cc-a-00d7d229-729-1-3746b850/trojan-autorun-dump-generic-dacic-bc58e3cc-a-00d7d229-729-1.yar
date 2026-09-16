rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_729_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_729_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dfee66fa1ce9f03742230b32a6314546e546fab86ea5837a152fe69e34734392"

  strings:
    $s1 = "&your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}