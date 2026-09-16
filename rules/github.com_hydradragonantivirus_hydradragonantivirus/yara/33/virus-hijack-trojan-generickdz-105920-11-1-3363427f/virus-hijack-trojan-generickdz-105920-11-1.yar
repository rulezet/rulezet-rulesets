rule Virus_Hijack_Trojan_GenericKDZ_105920_11_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105920_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "acfce170fe80ea7b4a4c56aa215caa7c50847ab949f3bb507642788c4c9ec620"

  strings:
    $s1 = "kYAT)?" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}