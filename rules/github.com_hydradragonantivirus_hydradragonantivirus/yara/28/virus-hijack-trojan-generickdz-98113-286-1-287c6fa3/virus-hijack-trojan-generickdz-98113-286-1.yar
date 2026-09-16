rule Virus_Hijack_Trojan_GenericKDZ_98113_286_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_286_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a349521ee01c9dede276d8ae5d0471521855b096272e2dbb552f7a43ce16b4d5"

  strings:
    $s1 = "{@sEit<.i/X" fullword ascii
    $s2 = "@<YiLL" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}