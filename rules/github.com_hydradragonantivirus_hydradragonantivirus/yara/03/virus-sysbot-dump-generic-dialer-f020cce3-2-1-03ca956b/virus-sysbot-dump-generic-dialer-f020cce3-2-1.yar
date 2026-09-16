rule Virus_Sysbot_Dump_Generic_Dialer_F020CCE3_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.F020CCE3_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "07336f5d414aa12673bab0cf2f3629cb2894c0c2c9dfc40aa076a75c9453f130"

  strings:
    $s1 = "diSK{)2" fullword ascii
    $s2 = "u]GIRR]" fullword ascii
    $s3 = "p<pahI" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}