rule Virus_Hijack_Trojan_GenericKDZ_98388_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a947012e50bf625e502c2ec55b2dd41af20a1dc0fb3c3e7f8ceb26a1a79ae7dd"

  strings:
    $s1 = "$@DALk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}