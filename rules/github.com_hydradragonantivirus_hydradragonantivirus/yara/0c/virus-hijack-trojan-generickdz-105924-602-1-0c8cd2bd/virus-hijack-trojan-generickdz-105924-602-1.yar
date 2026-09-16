rule Virus_Hijack_Trojan_GenericKDZ_105924_602_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_602_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "697c1d6051ce5c65838e3f5cba28c8479e9205d38751a508ae21c61bcf009277"

  strings:
    $s1 = " ?ROar" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}