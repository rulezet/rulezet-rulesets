rule Virus_Hijack_Trojan_GenericKDZ_105924_74_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_74_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "77c78a2e166d11bf379009bdc31e6d407bbdf6a02572730578b743c63370e1a2"

  strings:
    $s1 = "cR>dayS" fullword ascii
    $s2 = "qUeY>^" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}