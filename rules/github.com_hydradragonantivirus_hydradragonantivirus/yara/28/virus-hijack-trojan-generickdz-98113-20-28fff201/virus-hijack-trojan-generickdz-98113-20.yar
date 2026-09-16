rule Virus_Hijack_Trojan_GenericKDZ_98113_20 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_20.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb870ec9e38b99a839db0c0e6d4fa14f89b3780bafa3af8bdaf3e0ab3fd12674"

  strings:
    $s1 = "(Por service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}