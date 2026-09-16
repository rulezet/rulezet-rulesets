rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_194 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_194.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "084d5aa41281932a4f610175faf8091b720afd50b475985c56c56957604dd5ff"

  strings:
    $s1 = "MVprevent either party from disclosing the terms o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}