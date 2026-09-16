rule Virus_Hijack_Trojan_GenericKDZ_98113_55 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_55.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ef6be1cbb01ccf299fe630f56634502c0bffd29a22787fba45a797285ea0640"

  strings:
    $s1 = "PRAu;Z>" fullword ascii
    $s2 = ")prAu;z" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}