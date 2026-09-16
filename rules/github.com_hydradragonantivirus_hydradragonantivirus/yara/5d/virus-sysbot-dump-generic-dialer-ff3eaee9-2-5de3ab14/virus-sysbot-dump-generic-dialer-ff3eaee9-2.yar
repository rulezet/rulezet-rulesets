rule Virus_Sysbot_Dump_Generic_Dialer_FF3EAEE9_2 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.FF3EAEE9_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a805cc3d7fde50362eb1fdbc7d29184d6592bd23590b5c81c20387f57373bf9c"

  strings:
    $s1 = "soja!W" fullword ascii
    $s2 = "pUsh]l" fullword ascii
    $s3 = "(guss," fullword ascii
    $s4 = "J,SuLK" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}