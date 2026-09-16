rule Virus_Sysbot_Dump_Generic_Dialer_BEBD122F_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.BEBD122F_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a86f2c2a5dbbb7081a7e2682b190e6a5790dcf4c9dce040e2e037fd16d3295be"

  strings:
    $s1 = "MAnSe<R%k" fullword ascii
    $s2 = "+Q#LORY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}