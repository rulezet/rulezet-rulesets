rule Virus_Hijack_Trojan_GenericKDZ_105924_439_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_439_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18168077b924a9b93b1d573dd62770dbb152eb449f7f92b8dc9c25cd5f62644a"

  strings:
    $s1 = " FLAn$" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}