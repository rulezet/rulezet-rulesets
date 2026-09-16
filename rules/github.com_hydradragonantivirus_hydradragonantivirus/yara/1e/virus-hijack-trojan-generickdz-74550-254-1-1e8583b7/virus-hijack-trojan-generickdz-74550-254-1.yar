rule Virus_Hijack_Trojan_GenericKDZ_74550_254_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_254_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f13fda937864b0c53674945298c82aa2bde664d78441024cdbbaa5a40632aae"

  strings:
    $s1 = "dRaT'!}" fullword ascii
    $s2 = "PUmP Rg" fullword ascii
    $s3 = "o#Sizy" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}