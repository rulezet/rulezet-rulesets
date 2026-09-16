rule Virus_Hijack_Trojan_GenericKDZ_74550_123 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_123.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "980a66cf884612094ab0aaac4b5168baeaef2e5d8bf62effdabd422162523fbe"

  strings:
    $s1 = "Dir `/srv/git/wk_mkchild/var/url_processor` is empty. Sleep and goto new cycle" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}