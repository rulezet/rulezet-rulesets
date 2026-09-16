rule Virus_Hijack_Trojan_GenericKDZ_103285_426 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_426.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "07c1d7e98f87c8c98d920d122079d74e7e97813b3e93286c55ca90ae1cc43e53"

  strings:
    $s1 = "=^policy, which might require you to return the software with the entire computer on which the software is" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}