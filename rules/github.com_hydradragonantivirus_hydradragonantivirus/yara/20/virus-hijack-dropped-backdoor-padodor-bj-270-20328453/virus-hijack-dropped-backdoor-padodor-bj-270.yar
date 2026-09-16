rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_270 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_270.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82463338605ac755ea623c39394bae5a3a5e38c0f033ad6277a84dab32257367"

  strings:
    $s1 = "]Ware a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}