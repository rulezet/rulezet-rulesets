rule Virus_Hijack_Trojan_GenericKDZ_79663_83_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_83_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4400030fee8ee1d05bf65ce8ff223fc8de29be9723a142ddd51d5eaca0700da"

  strings:
    $s1 = ",<tWaY`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}