rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_212_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_212_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "860faf6a77a5912d525ec9cc06bc7b8fddcdc0be8f4d990ff66a0a5dd0f1b960"

  strings:
    $s1 = "+vOracle does not warrant that the Oracle Universi" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}