rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_774_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_774_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82dd2bc7a30f41f8ab6e65d557be014166715b9ee8032aac091123a736c80a89"

  strings:
    $s1 = "mendable" fullword wide
    $s2 = "Subabdominal" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}