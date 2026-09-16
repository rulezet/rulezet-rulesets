rule Virus_Hijack_Trojan_GenericKDZ_105921_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105921_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7928764c2fb399411c0b431688474518ff33630aea167eec73c41986e6d6d67"

  strings:
    $s1 = "/}2013 software. For your convenience, we" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}