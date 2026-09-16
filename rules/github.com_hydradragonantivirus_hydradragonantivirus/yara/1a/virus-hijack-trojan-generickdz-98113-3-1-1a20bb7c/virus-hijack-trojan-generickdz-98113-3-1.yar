rule Virus_Hijack_Trojan_GenericKDZ_98113_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "45c5a532e4bdf1b4cbfe4453595f6abdbc811633138dee844d81c56840d46b2f"

  strings:
    $s1 = "ziZZ,}=hx" fullword ascii
    $s2 = "sidY,Y" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}