rule Virus_Sysbot_Dump_Generic_Dialer_BEBD122F_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.BEBD122F_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da3327be43d5108b7eac91e9e7e1dfed9c02b3e0cc0455347a0d46c3fecc5f1c"

  strings:
    $s1 = "Dear?4" fullword ascii
    $s2 = "~!sifE" fullword ascii
    $s3 = "t*POXy" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}