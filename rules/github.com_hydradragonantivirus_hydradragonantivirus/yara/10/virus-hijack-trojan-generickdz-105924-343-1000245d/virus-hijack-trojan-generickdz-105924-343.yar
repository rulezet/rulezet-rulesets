rule Virus_Hijack_Trojan_GenericKDZ_105924_343 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_343.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a63847da7af89fc97e8bb52604b8c79f0fa70fd8823966cbd37a97447972a0c"

  strings:
    $s1 = "jW(WroX" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}