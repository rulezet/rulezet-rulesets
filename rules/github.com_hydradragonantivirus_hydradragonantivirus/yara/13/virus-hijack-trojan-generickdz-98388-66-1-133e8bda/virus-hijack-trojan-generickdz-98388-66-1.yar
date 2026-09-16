rule Virus_Hijack_Trojan_GenericKDZ_98388_66_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_66_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6aa2a7f64d197d8283c4794759f46f5f5f91c5b234553f17bffa7fd0978bb3b2"

  strings:
    $s1 = "gL#NOOk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}