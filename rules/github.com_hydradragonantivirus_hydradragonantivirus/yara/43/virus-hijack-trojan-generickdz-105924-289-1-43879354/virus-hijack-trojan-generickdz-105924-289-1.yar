rule Virus_Hijack_Trojan_GenericKDZ_105924_289_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_289_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85b9e9707a674d948223e13c2b5ef9cdbdcda6730f151e6ea7499c7e360bb4ac"

  strings:
    $s1 = "oolOgY" fullword ascii
    $s2 = "2$'vt*BAil" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}