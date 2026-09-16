rule Virus_Hijack_Trojan_GenericKDZ_105924_394_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_394_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f03354076b0292baa3347e0366f4980404b18eb62a473bb7d55b1bb690c42f2e"

  strings:
    $s1 = "coRm$L" fullword ascii
    $s2 = ":YeES[" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}