rule Virus_Sysbot_Dump_Generic_Dialer_BEBD122F_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.BEBD122F_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ebc687c6eee6bd9eb850c4c5b718ed7f13e6c8b32431223d2e4ee5b43420d811"

  strings:
    $s1 = "5$Lunn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}