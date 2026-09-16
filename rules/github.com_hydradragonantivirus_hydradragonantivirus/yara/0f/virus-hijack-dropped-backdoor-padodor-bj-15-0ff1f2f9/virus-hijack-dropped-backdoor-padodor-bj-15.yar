rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_15 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_15.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96434e1054a6d2f7423ec7218f992f7029a74bb9215303e1dcf892b7b501aae3"

  strings:
    $s1 = "pprevent either party from disclosing the terms o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}