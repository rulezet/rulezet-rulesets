rule Virus_Hijack_Gen_Trojan_ShellObject_q8Z_aCkwazk_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aCkwazk_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c24833079d99a98914dbfcb3a084fa4e25cb860480d465b32952fa37b4fb396b"

  strings:
    $s1 = "\"FoUn[" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}