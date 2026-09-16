rule Virus_Hijack_Trojan_GenericKDZ_98113_327 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_327.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8fc20b079ee2e6d4fcb6c5b803de691fe71114077c8f4ae7523403ef45d908ab"

  strings:
    $s1 = "Z$hundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}