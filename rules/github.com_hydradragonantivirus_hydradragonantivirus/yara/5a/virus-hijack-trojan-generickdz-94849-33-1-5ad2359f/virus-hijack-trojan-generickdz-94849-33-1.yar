rule Virus_Hijack_Trojan_GenericKDZ_94849_33_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.94849_33_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d4ce8236b00b6ac4853b0fa437eab996c0e9c371109606184004a25712dbe7e"

  strings:
    $s1 = "OdsO H" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}