rule Virus_Hijack_Trojan_GenericKDZ_105924_435_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_435_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3a2e55a40a534d1ee884853757e4f3e9e17215243fe0f454818580081217208"

  strings:
    $s1 = "o\"yoLKY" fullword ascii
    $s2 = "@H#&Feis" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}