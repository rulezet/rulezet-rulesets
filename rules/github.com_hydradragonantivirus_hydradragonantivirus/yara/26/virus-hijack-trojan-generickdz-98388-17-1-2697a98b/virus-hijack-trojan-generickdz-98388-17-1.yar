rule Virus_Hijack_Trojan_GenericKDZ_98388_17_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_17_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fab5675a78f42ee852940fb225c4209f14b8c97eb7f679a04223c79927d58154"

  strings:
    $s1 = "]lEwD?" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}