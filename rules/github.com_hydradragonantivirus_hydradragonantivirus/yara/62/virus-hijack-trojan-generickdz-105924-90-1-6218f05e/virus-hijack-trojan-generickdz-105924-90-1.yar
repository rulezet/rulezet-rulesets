rule Virus_Hijack_Trojan_GenericKDZ_105924_90_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_90_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2efc6396a6cdd5b4c1db002605fd6e43038e8eb69a31913ded149cab53b49e7"

  strings:
    $s1 = "SPorE%" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}