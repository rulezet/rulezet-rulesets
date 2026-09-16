rule Virus_Sysbot_Dump_Generic_Dialer_5485D7ED_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.5485D7ED_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8dbd584eb9d23bfc08235aaf7600665fe1a05e184572a1fdc2a1573b3d13cbe"

  strings:
    $s1 = "k2?YAba" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}