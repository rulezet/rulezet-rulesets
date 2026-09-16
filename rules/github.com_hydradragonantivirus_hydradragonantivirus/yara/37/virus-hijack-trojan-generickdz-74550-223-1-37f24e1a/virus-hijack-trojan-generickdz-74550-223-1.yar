rule Virus_Hijack_Trojan_GenericKDZ_74550_223_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_223_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dae636ba7978ea4e70f2471a2189f4c4b423b9a7dbe2f2e6fd7bf999d2cfc3ea"

  strings:
    $s1 = "sauF{/" fullword ascii
    $s2 = "U$pArr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}