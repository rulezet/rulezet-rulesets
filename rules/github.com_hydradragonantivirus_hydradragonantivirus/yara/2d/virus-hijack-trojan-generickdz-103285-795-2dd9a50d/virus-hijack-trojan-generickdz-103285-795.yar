rule Virus_Hijack_Trojan_GenericKDZ_103285_795 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_795.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30598adf27f902ef4e167f8807a6b3cf89918110335c8d3124b1a8ef184f735b"

  strings:
    $s1 = "ujSoftware Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}