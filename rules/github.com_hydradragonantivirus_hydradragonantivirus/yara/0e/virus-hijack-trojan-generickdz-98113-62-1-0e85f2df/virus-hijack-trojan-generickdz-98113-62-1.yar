rule Virus_Hijack_Trojan_GenericKDZ_98113_62_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_62_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "321832fd912f1d551238f94564c966e2f96062ee6bc503d786ea1dd2f25be42c"

  strings:
    $s1 = "L inRO" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}