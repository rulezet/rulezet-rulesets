rule Virus_Hijack_Trojan_GenericKDZ_105924_517_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_517_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "def8ca41f06e4c5b4b90045d490f784aa0738a1a16da9420662e29a9f702ba90"

  strings:
    $s1 = "=P LAsT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}