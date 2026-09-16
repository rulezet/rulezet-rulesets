rule Virus_Sysbot_Dump_Generic_Dialer_F020CCE3_9 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.F020CCE3_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6d271ae2f1de9a0f59c5f4e9aa0825c16a7d1b9f3a30b315d64b0a05fd7ca98"

  strings:
    $s1 = "@!mUTT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}