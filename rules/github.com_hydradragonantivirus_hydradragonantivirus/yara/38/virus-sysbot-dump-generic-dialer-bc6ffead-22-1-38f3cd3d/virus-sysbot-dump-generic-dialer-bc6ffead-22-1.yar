rule Virus_Sysbot_Dump_Generic_Dialer_BC6FFEAD_22_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.BC6FFEAD_22_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9892cc3e0685c0d5fdfb446f4588cc9119c07e9970fdf30eae45663c902ac873"

  strings:
    $s1 = ")Vage<" fullword ascii
    $s2 = "nEAt;O" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}