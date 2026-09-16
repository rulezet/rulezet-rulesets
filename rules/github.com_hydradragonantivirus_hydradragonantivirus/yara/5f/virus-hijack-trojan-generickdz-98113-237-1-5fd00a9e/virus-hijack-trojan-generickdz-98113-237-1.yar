rule Virus_Hijack_Trojan_GenericKDZ_98113_237_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_237_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "99cd741e28ab474407b3cea73962456c614084d2fa7cda4358d0257c7db0975d"

  strings:
    $s1 = "f[fLit" fullword ascii
    $s2 = "2>mARY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}