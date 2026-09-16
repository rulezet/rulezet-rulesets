rule Virus_Hijack_Trojan_GenericKDZ_79663_28_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_28_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cfed3a2d84f05f644d4e66fa903cb90c2ee922b52b01cb6120d4f7357bbdec81"

  strings:
    $s1 = "sOsS(\\" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}