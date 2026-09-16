rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_803_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_803_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4dff6fa5192af407110ed88803a1282bcbd953755e740542d7521364f032fe0"

  strings:
    $s1 = "wthe licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}