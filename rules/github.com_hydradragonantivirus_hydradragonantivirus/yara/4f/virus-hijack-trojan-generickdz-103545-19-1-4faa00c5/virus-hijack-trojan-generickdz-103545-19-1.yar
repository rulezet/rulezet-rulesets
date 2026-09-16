rule Virus_Hijack_Trojan_GenericKDZ_103545_19_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_19_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5978f002ac6318354a55ebffc3a8e42786e5d66111ed24b79ade8b77aa7a415"

  strings:
    $s1 = " mUID,&" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}