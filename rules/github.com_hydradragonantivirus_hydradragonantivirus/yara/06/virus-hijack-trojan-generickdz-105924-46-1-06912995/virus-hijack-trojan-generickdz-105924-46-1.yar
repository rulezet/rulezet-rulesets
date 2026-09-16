rule Virus_Hijack_Trojan_GenericKDZ_105924_46_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_46_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f13df73889b43fe77f66d2cc9cfee1953651a7803693ef838caa2e34cf55318a"

  strings:
    $s1 = " (ZArf" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}