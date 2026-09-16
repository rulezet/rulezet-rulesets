rule Virus_Hijack_Trojan_GenericKDZ_98388_171_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_171_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29aeb29e0d203d814d98a3ce261460c67c6c37342ac77a19ee6b2eaa8f82ef6b"

  strings:
    $s1 = "FACy'J" fullword ascii
    $s2 = "7q,baff" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}