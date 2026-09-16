rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_363_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_363_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71e856056a74b4b90a3e70a6277afcf9f9f51cb562a50ffeb73728ab0f294a36"

  strings:
    $s1 = "i5are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}