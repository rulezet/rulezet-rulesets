rule Virus_Hijack_Trojan_GenericKDZ_105924_400_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_400_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2cbad0a05f62b0ade5296c6fd4271eb040da49f73970845832ffe0abb149328a"

  strings:
    $s1 = "+}BUzZ`Mz" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}