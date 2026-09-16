rule Virus_Hijack_Trojan_GenericKDZ_98113_134_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_134_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39f6d02b88dfee98ce8e00f97eaf1ce5fba7c607099896286ee1225c8cee4e45"

  strings:
    $s1 = "7[torU" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}