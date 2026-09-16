rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_662 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_662.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0eaa104d7b7191e7534a00e33e859df5e1c00d27e998cb473d61dc313ebfd03"

  strings:
    $s1 = "+prevent either party from disclosing the terms o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}