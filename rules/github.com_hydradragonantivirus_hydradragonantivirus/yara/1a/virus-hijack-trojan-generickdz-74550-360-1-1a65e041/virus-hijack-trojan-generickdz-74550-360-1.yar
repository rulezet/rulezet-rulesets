rule Virus_Hijack_Trojan_GenericKDZ_74550_360_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_360_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce65a564b94077fb7537b5c1ebdb969c7af308a8b9b1dba6016094c74a23c40a"

  strings:
    $s1 = "_?yOUr" fullword ascii
    $s2 = "@noiR)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}