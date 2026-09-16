rule Virus_Hijack_Trojan_GenericKDZ_98388_80_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_80_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f9080cc683a3c613f555ccdb5573e739ffdf9dfdaffada6a9b0a3343c3a19f2"

  strings:
    $s1 = "FULL&K4" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}