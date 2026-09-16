rule Virus_Hijack_Trojan_GenericKDZ_99416_15_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_15_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "079de98fc40e8d922369ea927a637ea976efa8ae020f9849711ef656ffccb0fc"

  strings:
    $s1 = "haNK?A" fullword ascii
    $s2 = "d!&(LoIn" fullword ascii
    $s3 = "wARP)<" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}