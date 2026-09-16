rule Virus_Hijack_Trojan_GenericKDZ_103285_256 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_256.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3477ae266f68af8c7f369312541ed5e47d0ae3f611d797f07044ccfe6d985ea6"

  strings:
    $s1 = "9a neutral arbitrator, whose decision will be final except for a limited right of appeal under the Federal" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}