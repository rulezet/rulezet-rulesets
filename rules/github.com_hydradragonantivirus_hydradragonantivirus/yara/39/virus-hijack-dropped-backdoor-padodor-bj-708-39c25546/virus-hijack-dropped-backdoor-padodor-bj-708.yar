rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_708 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_708.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf37d9dcc9c341c229e336debb9992ff08449819a865e8e68f18d200f0c0f26c"

  strings:
    $s1 = "eand services at the list price in effect at the " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}