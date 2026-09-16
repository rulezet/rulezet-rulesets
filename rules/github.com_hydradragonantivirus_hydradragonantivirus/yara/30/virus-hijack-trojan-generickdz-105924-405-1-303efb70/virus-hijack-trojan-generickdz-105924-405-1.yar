rule Virus_Hijack_Trojan_GenericKDZ_105924_405_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_405_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ecb0adef4a917d968af732113781bca4edc8ff0e49f0827a903ccc555e790fe2"

  strings:
    $s1 = "}ruFf>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}