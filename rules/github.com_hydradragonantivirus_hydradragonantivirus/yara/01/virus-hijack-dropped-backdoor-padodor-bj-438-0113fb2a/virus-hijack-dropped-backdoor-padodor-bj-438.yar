rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_438 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_438.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c35aa3985a22846092e61d21349d272491b974de08cf473da876694bc27cc07"

  strings:
    $s1 = "-prevent either party from disclosing the terms o" fullword ascii
    $s2 = "hide:i" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}