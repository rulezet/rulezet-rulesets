rule Virus_Hijack_Trojan_GenericKDZ_105924_62_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_62_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f3e21982ddd579d58d98496fd2f1d98ea460b2ad8293006e76851fa7a37b50c"

  strings:
    $s1 = "}fAvn&" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}