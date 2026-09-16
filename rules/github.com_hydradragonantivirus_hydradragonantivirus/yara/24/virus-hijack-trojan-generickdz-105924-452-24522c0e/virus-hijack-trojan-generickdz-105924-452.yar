rule Virus_Hijack_Trojan_GenericKDZ_105924_452 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_452.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f97c88573b43c1b86c7bc5c75cee050957107ccb1f24eee9396260f736bd9be2"

  strings:
    $s1 = "MaLI!M|YY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}