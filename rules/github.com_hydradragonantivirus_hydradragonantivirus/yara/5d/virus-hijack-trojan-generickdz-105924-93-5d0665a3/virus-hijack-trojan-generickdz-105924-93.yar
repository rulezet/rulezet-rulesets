rule Virus_Hijack_Trojan_GenericKDZ_105924_93 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_93.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7300dcabd0352f85f63e102659d034b72f4b5a3bf72d2fc936eea3f999d89b1f"

  strings:
    $s1 = "/NnTLf\"rAng" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}