rule Virus_Hijack_Trojan_GenericKDZ_103285_81 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_81.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af7de3c3355ea231227c8d09f9630930a2efb2b6c5515a1d0fc041443cb552cf"

  strings:
    $s1 = "BesrA " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}