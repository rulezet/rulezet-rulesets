rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_612 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_612.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "747aea147c8ccf1625f580825efe37015463367f6c53d43a194419d11f365242"

  strings:
    $s1 = "oprevent either party from disclosing the terms o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}