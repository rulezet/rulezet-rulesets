rule Virus_Hijack_Trojan_GenericKDZ_105924_456_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_456_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d6f2e744b5a0a9a1eb0ea11f35367b9ad1810dfee996cd1dac51b4322392262"

  strings:
    $s1 = "zaiN)tH" fullword ascii
    $s2 = "V(auRa@%" fullword ascii
    $s3 = "K CUSP&" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}