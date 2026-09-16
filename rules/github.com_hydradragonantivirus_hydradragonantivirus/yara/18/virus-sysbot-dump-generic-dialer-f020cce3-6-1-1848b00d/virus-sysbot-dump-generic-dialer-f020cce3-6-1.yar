rule Virus_Sysbot_Dump_Generic_Dialer_F020CCE3_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.F020CCE3_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1f8a3b8c978d351bdc29579834ae14d369bd3aa7399ba1a33208f92fe809339"

  strings:
    $s1 = "ilOT`e" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}