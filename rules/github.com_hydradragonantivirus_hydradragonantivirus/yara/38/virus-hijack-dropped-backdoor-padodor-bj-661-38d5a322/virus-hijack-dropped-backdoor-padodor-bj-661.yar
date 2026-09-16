rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_661 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_661.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21ec9ab5ae5974598e604847f2d18f7c8961e0a99fc2888f01f18196c41f263d"

  strings:
    $s1 = "\"prevent either party from disclosing the terms o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}