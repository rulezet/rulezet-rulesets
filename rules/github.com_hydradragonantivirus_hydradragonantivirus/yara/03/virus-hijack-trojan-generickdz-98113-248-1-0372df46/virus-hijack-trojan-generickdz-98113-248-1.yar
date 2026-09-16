rule Virus_Hijack_Trojan_GenericKDZ_98113_248_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_248_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d0f059ee78836d883c24ce50f8e14884bf8467809fd12169eed7179e4b7487f"

  strings:
    $s1 = "kNeZ# " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}