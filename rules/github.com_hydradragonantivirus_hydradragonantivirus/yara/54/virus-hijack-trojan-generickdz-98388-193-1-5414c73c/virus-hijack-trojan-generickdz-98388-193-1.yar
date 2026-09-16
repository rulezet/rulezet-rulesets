rule Virus_Hijack_Trojan_GenericKDZ_98388_193_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_193_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2bd6ada84581cbe19e192ac6d52600ee9d8204199779fb29bb3a12267ac0510a"

  strings:
    $s1 = "exIt%E" fullword ascii
    $s2 = "sIeR j9*G" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}