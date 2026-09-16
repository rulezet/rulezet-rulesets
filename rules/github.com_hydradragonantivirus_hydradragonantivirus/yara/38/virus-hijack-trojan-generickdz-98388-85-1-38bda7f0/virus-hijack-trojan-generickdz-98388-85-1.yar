rule Virus_Hijack_Trojan_GenericKDZ_98388_85_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_85_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6486cdbd901a4595d90df7e9dc46277f7c5aa848640b417deccde8032941472c"

  strings:
    $s1 = "HULl<O" fullword ascii
    $s2 = "h]jUPE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}