rule Virus_Hijack_Trojan_GenericKDZ_105924_343_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_343_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d034f8071684e8fa30d78fd4a5e7f26da0186fd4d8f9c80d89c337253fd2c3ca"

  strings:
    $s1 = "qUEy[u" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}