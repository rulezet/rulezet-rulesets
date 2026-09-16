rule Virus_Hijack_Trojan_GenericKDZ_105924_502_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_502_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03d24344b16e2dd83413e8fab871150f9fb90e48f46ed20d357b5d221858b779"

  strings:
    $s1 = ",zANy:~" fullword ascii
    $s2 = "H?joBo" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}