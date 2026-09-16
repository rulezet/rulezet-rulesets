rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_236_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_236_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a590aef6bf2b932ca40ed4c0fa30cdc1ca85697b991d9ad1ca7f0eb191ea8528"

  strings:
    $s1 = "_6are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}