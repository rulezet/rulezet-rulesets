rule Trojan_Hooker_Dump_Generic_Dacic_464_F9526DF5_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Dump.Generic.Dacic.464.F9526DF5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbef14a6dc5d4f03f12b1399a1c7d884b9bf1351b875fe3825ea3363a4e1ec65"

  strings:
    $s1 = "netsh winsock reset" fullword ascii
    $s2 = "(SOCKET s)" fullword ascii
    $s3 = "Fatal Error, SPI can't create GMEM lock" fullword ascii
    $s4 = "RIFF m" fullword ascii
    $s5 = "nJ:<HEWt" fullword ascii
    $s6 = "SPI can't create GMem lock" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}