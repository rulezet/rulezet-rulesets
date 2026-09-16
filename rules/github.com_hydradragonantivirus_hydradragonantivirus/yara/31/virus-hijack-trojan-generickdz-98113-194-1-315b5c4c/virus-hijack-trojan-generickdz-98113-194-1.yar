rule Virus_Hijack_Trojan_GenericKDZ_98113_194_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_194_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e9bd54a80f9d4a5d97c42549f53c2e45d2390fc74af60bad698dfb7f75e9b75"

  strings:
    $s1 = "S:THoO" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}