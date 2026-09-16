rule Virus_Hijack_Trojan_GenericKDZ_103285_498 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_498.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61db2593709cbbd9b25d509e748469aa63291c3b5b1249dd7d9818e2225c2793"

  strings:
    $s1 = "NUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}