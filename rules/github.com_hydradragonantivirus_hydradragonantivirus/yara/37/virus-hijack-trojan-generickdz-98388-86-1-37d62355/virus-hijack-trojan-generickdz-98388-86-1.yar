rule Virus_Hijack_Trojan_GenericKDZ_98388_86_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_86_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f90e3e578d359fde33de3bd70142ce10596c37a040b5d47009e823f1378173a0"

  strings:
    $s1 = "traP(O1K" fullword ascii
    $s2 = "(Acyl;" fullword ascii
    $s3 = "(%bEAN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}