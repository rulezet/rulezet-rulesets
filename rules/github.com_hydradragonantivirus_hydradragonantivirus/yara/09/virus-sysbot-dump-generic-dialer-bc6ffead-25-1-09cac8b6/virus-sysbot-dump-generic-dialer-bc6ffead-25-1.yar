rule Virus_Sysbot_Dump_Generic_Dialer_BC6FFEAD_25_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.BC6FFEAD_25_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41e4dab478ae025ada10a1d848a8d2086b864154b66a0b5159a4219f7d59b98e"

  strings:
    $s1 = "F>ream" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}