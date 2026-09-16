rule Virus_Hijack_Trojan_GenericKDZ_105924_136_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_136_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "799f2a79c0a4ad0574efa1834fb1d94ecf8e1b4a5ca22425ce2be68f822432a9"

  strings:
    $s1 = "xservr Version 1.0" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}