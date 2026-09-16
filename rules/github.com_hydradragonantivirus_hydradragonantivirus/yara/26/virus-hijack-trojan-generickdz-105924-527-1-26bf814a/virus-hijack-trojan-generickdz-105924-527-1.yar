rule Virus_Hijack_Trojan_GenericKDZ_105924_527_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_527_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bfad79b5104e36c320a19115311e957873b499c9d0956719e46cd8e56190eba8"

  strings:
    $s1 = "g}BoCe" fullword ascii
    $s2 = "*?BIlE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}