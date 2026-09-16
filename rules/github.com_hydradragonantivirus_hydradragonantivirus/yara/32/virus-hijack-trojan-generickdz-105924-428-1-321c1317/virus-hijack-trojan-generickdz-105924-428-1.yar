rule Virus_Hijack_Trojan_GenericKDZ_105924_428_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_428_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d51854550e2f345f5c9cf879276640d2639ca805b57260fac7d1ed5f9b6e4e8"

  strings:
    $s1 = "SpUd<," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}