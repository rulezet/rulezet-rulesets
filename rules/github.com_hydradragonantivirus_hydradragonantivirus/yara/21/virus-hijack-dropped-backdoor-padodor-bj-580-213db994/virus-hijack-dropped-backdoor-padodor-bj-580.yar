rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_580 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_580.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1fba3846404ba99b1c3f40ec738a1f6f88ecddb91b6241b9f4154067d59c5f08"

  strings:
    $s1 = "m)prevent either party from disclosing the terms o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}