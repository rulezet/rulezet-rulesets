rule Virus_Sysbot_Dump_Generic_Dialer_E5D8CA99_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.E5D8CA99_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9cc1907d906941e956a1e27b0682d5e08c6070c232022f4492b1ab1e36c96725"

  strings:
    $s1 = "AReD!M" fullword ascii
    $s2 = "i%BeLD" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}