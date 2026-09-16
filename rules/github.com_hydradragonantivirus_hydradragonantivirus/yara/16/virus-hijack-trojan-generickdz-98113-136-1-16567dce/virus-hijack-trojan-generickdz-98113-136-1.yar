rule Virus_Hijack_Trojan_GenericKDZ_98113_136_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_136_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da6436c1d4a5080371a20f643310246ac08d7f24de9e378de41b71384f5239dd"

  strings:
    $s1 = ")PhiZ%" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}