rule Virus_Hijack_Trojan_GenericKDZ_74550_197_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_197_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96c795955077836eff240104ffc8ca3ee7b69c0b7097d16ae613e0a5e0f8c3bd"

  strings:
    $s1 = "dAUb]-" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}