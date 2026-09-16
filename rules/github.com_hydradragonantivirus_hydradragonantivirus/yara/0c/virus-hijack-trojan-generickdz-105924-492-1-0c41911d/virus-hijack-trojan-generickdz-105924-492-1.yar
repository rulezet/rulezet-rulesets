rule Virus_Hijack_Trojan_GenericKDZ_105924_492_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_492_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cdde5add4af545a98c13d26295637c72a9839c419de9152c6e8217a3836661b8"

  strings:
    $s1 = "UNde&96" fullword ascii
    $s2 = "&H{{LICk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}