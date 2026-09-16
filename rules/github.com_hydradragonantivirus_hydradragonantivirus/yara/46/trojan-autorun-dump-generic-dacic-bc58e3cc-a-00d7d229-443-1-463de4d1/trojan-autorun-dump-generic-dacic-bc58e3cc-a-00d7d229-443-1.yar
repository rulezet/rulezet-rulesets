rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_443_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_443_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "354ebd029c7af35c3cfa874f150f49f0d1b7893de5eed94a5d5def1a204cbf7c"

  strings:
    $s1 = "*are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}