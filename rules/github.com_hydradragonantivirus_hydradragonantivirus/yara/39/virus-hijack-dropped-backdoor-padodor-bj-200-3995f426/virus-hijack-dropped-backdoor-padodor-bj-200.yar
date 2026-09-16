rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_200 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_200.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54097e9e53ed1fca85fb34a62a4aab09a2d2245fe860b1088706d6c3ded40fff"

  strings:
    $s1 = "9prevent either party from disclosing the terms o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}