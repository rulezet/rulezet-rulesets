rule Virus_Hijack_Trojan_GenericKD_66277505 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKD.66277505.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a2aa41f7e57f146348dfb9afd23aadd063cba3e53c6cdd0c042554d42b4b1514"

  strings:
    $s1 = "OMFG Studio?Operating System" fullword wide
    $s2 = "About Clock" fullword wide
    $s3 = "OMFG Studio" fullword wide
    $s4 = "OMFG All rights reserved." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}