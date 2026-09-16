rule Virus_Hijack_Trojan_GenericKDZ_105924_117 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_117.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "953a9b43dc0513d12c6889cb3fef7ce2c35972aab942392819b67b9c54330ecc"

  strings:
    $s1 = "puFF#DFF" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}