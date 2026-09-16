rule Virus_Hijack_Trojan_GenericKDZ_98113_241_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_241_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db8469de83eca0137bf1dda9e2bc9aaa2cb9e9398afe9571fa781b623087c413"

  strings:
    $s1 = " G*BagA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}