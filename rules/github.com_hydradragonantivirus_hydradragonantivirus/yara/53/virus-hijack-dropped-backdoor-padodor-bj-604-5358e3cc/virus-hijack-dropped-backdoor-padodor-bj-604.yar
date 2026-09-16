rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_604 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_604.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a205607d29944a3df668dc5b7661be98876172a673b7b374084486bfdb54967"

  strings:
    $s1 = "Oracle does not warrant that the Oracle Universi" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}