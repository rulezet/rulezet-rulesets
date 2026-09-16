rule Virus_Hijack_Trojan_GenericKDZ_98113_280_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_280_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c010da2f65dd9d6bece236257cb742c80fe7d64acfa387d1dba87dec287fda1e"

  strings:
    $s1 = "SKoO(g/L" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}