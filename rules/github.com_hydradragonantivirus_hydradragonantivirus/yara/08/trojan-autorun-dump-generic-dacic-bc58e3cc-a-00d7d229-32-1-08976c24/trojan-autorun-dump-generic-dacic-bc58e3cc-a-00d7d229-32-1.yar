rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_32_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_32_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "211e50a17d29eddd24b31b5544b428f56e26f2dc5c28003451ad422635dfd372"

  strings:
    $s1 = "8iLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}