rule Virus_Hijack_Trojan_GenericKDZ_105924_330_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_330_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "828bb246a85f5062e85e709156c01b89ee9b6241d5277f7cb319ed3401a64fb8"

  strings:
    $s1 = "BaNi@V" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}