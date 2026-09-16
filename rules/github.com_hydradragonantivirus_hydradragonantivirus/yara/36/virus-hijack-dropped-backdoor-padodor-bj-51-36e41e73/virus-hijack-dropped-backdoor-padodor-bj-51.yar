rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_51 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_51.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3b5d7642b0ebaac29cd8b1c7c6f380b06d82c002dfe260fd9c40be9e5f5e40e"

  strings:
    $s1 = "-{are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}