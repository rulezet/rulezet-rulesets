rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_723 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_723.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61c004f99d7ccde29fd4c30aefa4c6730df02f4dfd54893dcf7c9cc5a9e6c88c"

  strings:
    $s1 = "prevent either party from disclosing the terms o" fullword ascii
    $s2 = "CLOT@ZO" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}