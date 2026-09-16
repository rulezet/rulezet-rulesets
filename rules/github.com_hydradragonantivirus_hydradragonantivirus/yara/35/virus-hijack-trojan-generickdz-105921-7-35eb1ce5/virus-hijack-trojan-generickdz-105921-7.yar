rule Virus_Hijack_Trojan_GenericKDZ_105921_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105921_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c154653bda72412e99cb244b0124eff2745c05d089436a2a300b757384d7480c"

  strings:
    $s1 = "informational links in this agreement. The links containing terms that bind you and`" fullword ascii
    $s2 = ":2013 software. For your convenience, we" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}