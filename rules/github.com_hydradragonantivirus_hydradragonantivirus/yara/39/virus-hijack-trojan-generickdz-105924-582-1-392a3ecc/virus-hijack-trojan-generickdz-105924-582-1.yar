rule Virus_Hijack_Trojan_GenericKDZ_105924_582_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_582_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2220696e22cea05dc42ec3abcd959feba313dc52099c2bbc96b54c14ba6a4e1"

  strings:
    $s1 = "COny{HZ" fullword ascii
    $s2 = ")#TOOk" fullword ascii
    $s3 = "u}ToCO" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}