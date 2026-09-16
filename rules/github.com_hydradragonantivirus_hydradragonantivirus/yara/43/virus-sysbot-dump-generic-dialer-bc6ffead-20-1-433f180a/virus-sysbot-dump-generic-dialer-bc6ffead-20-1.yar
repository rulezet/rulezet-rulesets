rule Virus_Sysbot_Dump_Generic_Dialer_BC6FFEAD_20_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.BC6FFEAD_20_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbcaa4128139cb3ddb425b9232ba6ab3dc5c90035fd9247eedd4431aa4a3c9ca"

  strings:
    $s1 = "A;{GROt" fullword ascii
    $s2 = "DOUt[@" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}