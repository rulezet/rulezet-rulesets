rule Virus_Hijack_Trojan_GenericKDZ_105924_414_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_414_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "433220fe5317eaa19f2ea5a194a24a72b982756952ed4b96bfbae75848f586c9"

  strings:
    $s1 = "gANe!:" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}