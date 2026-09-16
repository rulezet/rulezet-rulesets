rule Virus_Hijack_Trojan_GenericKDZ_98388_233_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_233_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d481ce007037bbf53a0586a2abf1cfc4d47c680b068e6c267c314de5d5b89719"

  strings:
    $s1 = "UVaL'u" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}