rule Virus_Hijack_Trojan_GenericKDZ_74550_289_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_289_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cdb9caf23a909940d5a3dac35c82f20c7581dbd3e14769bc49fb86c014a6c9c"

  strings:
    $s1 = "BlET<c@" fullword ascii
    $s2 = "WAlK]$" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}