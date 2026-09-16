rule Virus_Hijack_Trojan_GenericKDZ_98388_227_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_227_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d584f42d67fdaf4214cf10f87bd06cb34c99803b9736ae719c02515d1798994"

  strings:
    $s1 = "Soul]\\" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}