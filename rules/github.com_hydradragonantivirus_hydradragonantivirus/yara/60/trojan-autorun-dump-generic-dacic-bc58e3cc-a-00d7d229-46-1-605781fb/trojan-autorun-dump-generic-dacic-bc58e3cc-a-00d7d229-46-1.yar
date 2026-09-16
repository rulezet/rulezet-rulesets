rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_46_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_46_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab3b475a42b4b9a8ef7a58e16fc63fe76ad1b2090e284af935dfeac8aea8bf47"

  strings:
    $s1 = "of Subscribers. If your busines" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}