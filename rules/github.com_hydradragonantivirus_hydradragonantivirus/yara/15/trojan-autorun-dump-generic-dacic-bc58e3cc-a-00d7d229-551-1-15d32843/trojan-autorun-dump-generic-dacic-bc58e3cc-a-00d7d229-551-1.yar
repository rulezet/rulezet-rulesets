rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_551_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_551_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cee1ce41b17f5bbc74a8d0d783183073a19a222ff4ccb31e2d25069de3ee22d"

  strings:
    $s1 = "@the licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}