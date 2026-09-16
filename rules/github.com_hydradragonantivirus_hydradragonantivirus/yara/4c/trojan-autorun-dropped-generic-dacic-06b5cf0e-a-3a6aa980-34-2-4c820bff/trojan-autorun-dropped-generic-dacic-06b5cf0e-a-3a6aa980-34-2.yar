rule Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_34_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_34_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "122aca6f57773f6a1e4caf44f9af91649f27eb3478ccddfdf55fd4b95cff4b5e"

  strings:
    $s1 = "saPO#\"" fullword ascii
    $s2 = "yaTI(h" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}