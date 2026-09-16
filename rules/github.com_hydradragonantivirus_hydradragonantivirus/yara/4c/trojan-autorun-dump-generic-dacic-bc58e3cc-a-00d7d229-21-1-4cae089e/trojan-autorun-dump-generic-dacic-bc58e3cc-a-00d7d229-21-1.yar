rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_21_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_21_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "812bc1e2a94b61d495d40126987b10a4ce0cef9f96d30d70bd8a8dab7997b56f"

  strings:
    $s1 = "n|and services at the list price in effect at the " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}