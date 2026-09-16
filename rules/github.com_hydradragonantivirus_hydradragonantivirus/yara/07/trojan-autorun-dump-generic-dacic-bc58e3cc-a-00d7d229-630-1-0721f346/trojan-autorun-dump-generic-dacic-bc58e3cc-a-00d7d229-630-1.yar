rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_630_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_630_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22137c802c3069b973142dd220e81c8b2ec6afd817cd2705d7737cddbc326f5e"

  strings:
    $s1 = "*the licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}