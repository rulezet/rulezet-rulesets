rule Virus_Hijack_Trojan_GenericKDZ_98388_128_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_128_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "630f8695983e7efcaa4c6165b78bdbf37582821a10c3992237175b3eb7bac161"

  strings:
    $s1 = "taCT}!" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}