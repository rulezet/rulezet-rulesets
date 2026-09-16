rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_696_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_696_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "757c54c3509652348b6b9746b34f1599d6f296d18605f65340166612e991d7b0"

  strings:
    $s1 = ".your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}