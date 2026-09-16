rule Virus_Sysbot_Dump_Generic_Dialer_BC6FFEAD_26 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.BC6FFEAD_26.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41c9e8bb8652fee3fb93a0bd1ed2096813153bdb99ddd90976c7e3c61eca10be"

  strings:
    $s1 = "aXLE}^" fullword ascii
    $s2 = "{#KneE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}