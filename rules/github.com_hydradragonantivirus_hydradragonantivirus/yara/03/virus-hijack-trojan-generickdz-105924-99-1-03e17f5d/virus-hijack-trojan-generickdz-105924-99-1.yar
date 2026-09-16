rule Virus_Hijack_Trojan_GenericKDZ_105924_99_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_99_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65627b25c350c1fa44c8cbf813e5953cb7dd39c166ac2c778c92d54b5f088b1c"

  strings:
    $s1 = "%aLgA!" fullword ascii
    $s2 = "S\\,ObOL" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}