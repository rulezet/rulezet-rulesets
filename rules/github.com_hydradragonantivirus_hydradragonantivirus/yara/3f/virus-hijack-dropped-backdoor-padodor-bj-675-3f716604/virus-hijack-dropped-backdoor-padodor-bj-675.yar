rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_675 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_675.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87ccdd9732951b1eb54aecdec965d5fffc950156c395767ebb700ce3e340ec00"

  strings:
    $s1 = "Iand services at the list price in effect at the " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}