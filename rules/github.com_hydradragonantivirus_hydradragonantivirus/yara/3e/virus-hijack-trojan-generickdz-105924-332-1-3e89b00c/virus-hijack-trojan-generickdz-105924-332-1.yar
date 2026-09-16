rule Virus_Hijack_Trojan_GenericKDZ_105924_332_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_332_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a68f6fd7102c400d1ec1af36a677e71eef85cb0984d938208d3abe40308b17e"

  strings:
    $s1 = "n\"liCk" fullword ascii
    $s2 = "^V)DIce" fullword ascii
    $s3 = "R#FUZE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}