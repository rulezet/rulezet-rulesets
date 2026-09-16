rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_764 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_764.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c50b1a1bd2b390c81a13e53733d760d0a644db50944addb053f190e526043f75"

  strings:
    $s1 = " ^prevent either party from disclosing the terms o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}