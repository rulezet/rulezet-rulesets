rule Virus_Hijack_Trojan_GenericKDZ_105924_72_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_72_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "723c309933134402e9b4b8a93aac0454bb8241f0a0bd5d340dd73fb365ee5e8b"

  strings:
    $s1 = "BYeE?P" fullword ascii
    $s2 = "W-@kLOm " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}