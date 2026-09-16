rule Virus_Hijack_Trojan_GenericKDZ_98388_195 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_195.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7179708ef4352ecd8313444908c22492fcadafeb7f606945c1e651419af781ad"

  strings:
    $s1 = "MetaLink has information on which products have been translated for the supported languages (http://metalink.oracle.c`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}