rule Virus_Hijack_Trojan_GenericKDZ_74550_382_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_382_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca45744f7b75b0bccb46d94bb13047e2feb3708e5aabe4c8e35512858ebe5795"

  strings:
    $s1 = "S@EAve;" fullword ascii
    $s2 = "CARK#M4XVX" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}