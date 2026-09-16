rule Virus_Hijack_Trojan_GenericKDZ_103285_302 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_302.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30c65889cb31f36edf3a2e645f2140c70af162c58b8f1b26293939b0d1612518"

  strings:
    $s1 = "pSoftware Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}