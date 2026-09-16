rule Trojan_Autorun_Dump_Trojan_GenericKDZ_95048_30_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Trojan.GenericKDZ.95048_30_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "edd8d9314788af09e6989be60eb372a27090948671e2a898ad509d04177e2740"

  strings:
    $s1 = "nyour entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}