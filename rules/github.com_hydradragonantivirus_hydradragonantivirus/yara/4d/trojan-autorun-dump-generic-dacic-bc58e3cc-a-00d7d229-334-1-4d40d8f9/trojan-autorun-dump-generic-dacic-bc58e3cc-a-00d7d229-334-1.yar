rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_334_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_334_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c284eadbc146a05484bcd5bdd9a6b408e070f7af3e60c92e7a62959b8bf5419"

  strings:
    $s1 = "/and services at the list price in effect at the " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}