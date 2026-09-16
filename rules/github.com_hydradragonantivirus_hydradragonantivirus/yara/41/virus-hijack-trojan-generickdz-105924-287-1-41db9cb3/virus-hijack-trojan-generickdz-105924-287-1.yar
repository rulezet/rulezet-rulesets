rule Virus_Hijack_Trojan_GenericKDZ_105924_287_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_287_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e0ffff96819deaa82e22ec5b3debb4013d5b23d63ba0b6e23e22ab3e4814d75"

  strings:
    $s1 = "lulu?ig" fullword ascii
    $s2 = "JeRL>S" fullword ascii
    $s3 = "yeLp)W" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}