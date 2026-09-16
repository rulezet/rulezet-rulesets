rule Virus_Sysbot_Dump_Generic_Dialer_BC6FFEAD_11_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.BC6FFEAD_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87e40663d3c0ff7bb07f7cd395a4dcd1d2f42e2f86123f71a032ad302b8ccd9b"

  strings:
    $s1 = "IZar$>sO" fullword ascii
    $s2 = "E]DAiS" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}