rule Virus_Hijack_Trojan_GenericKDZ_105924_537_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_537_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4213ff1ba1465b7360b6b2fb5ec76e5bc7bf68308a20a3586d2c68441f8b22c6"

  strings:
    $s1 = "rAVe#/" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}