rule Virus_Hijack_Trojan_GenericKDZ_99416_24 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_24.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4fcdbdb89b69bc4f3277c6c3406dca30dd8d8a3690e36cc1f2ddabff719cce8b"

  strings:
    $s1 = "eUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}