rule Virus_Hijack_Trojan_GenericKDZ_74550_196_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_196_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca5defce02bfb86410bfd20093763ef3851666ad69e1c772c8b1057efbce2295"

  strings:
    $s1 = "LITh{{" fullword ascii
    $s2 = ",luNa'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}