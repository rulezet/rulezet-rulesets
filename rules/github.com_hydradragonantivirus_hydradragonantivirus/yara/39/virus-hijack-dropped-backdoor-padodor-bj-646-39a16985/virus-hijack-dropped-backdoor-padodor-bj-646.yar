rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_646 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_646.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "362e384e182081961cba74968021a8f8d1cbd37f4af66947d552556192c5f8af"

  strings:
    $s1 = "(prevent either party from disclosing the terms o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}