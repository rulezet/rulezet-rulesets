rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_760 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_760.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37d7a0f7587288c2d6495f88cc73b91d073ccc109e22793ab4e8bab1f3403818"

  strings:
    $s1 = "j!are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}