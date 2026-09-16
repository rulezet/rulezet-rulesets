rule Virus_Hijack_Trojan_GenericKDZ_105924_390_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_390_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b26ec54443300de58ad76f827aac4de5b7593d70414571b7263f322af619db71"

  strings:
    $s1 = "4(LAve" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}