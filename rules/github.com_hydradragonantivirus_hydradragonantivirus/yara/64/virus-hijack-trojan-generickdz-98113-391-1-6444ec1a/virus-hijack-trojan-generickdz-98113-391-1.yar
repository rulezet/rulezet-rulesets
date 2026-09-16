rule Virus_Hijack_Trojan_GenericKDZ_98113_391_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_391_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f93ebf36a13c9b6e3aea5cd462038fb6b751c50501e13e26b2faa4d68258bc73"

  strings:
    $s1 = "yirk.[" fullword ascii
    $s2 = "}*TEND" fullword ascii
    $s3 = ">k{Lord" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}