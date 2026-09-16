rule Virus_Autorun_Trojan_GenericKDZ_94849_16_1 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Trojan.GenericKDZ.94849_16_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a33fd203d860c8b582600e1bd27bae444470e6468327283dcf8ce8a47c69c3ee"

  strings:
    $s1 = "plication Data\\Applicat~b" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}