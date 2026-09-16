rule Virus_Hijack_Trojan_GenericKDZ_98113_96_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_96_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "687ec695edaf76e852e5f10724ff2fe06c03c2fd2246ce77269da92201515605"

  strings:
    $s1 = "&jUBA}" fullword ascii
    $s2 = "v8$?tONk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}