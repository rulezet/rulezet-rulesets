rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_785_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_785_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "48b9176a14bb76e3744a18e34c0d48d56614624d47a5466faa8e79ab12ffc18e"

  strings:
    $s1 = "1the licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}