rule VirusShareTrojanSiggen1527075_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanSiggen1527075_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "16a4b0e5e103242edb311f1c5aae06ea875707ecd21d73948dc5977f2517f9e0"

  strings:
    $s1 = "Sh@sOlTNz2G2|?}aUto$#})zB^" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}