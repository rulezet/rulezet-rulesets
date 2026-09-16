rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_108 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_108.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "67cd38212efdb795479a9c37a01887a9bd5ecbfb48414a053ee46d1826e74fc5"

  strings:
    $s1 = "lp|lCwu.hp4l}n}-~g4lnmj>halL]n}-~g4lhll)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}