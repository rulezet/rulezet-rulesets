rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_248 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_248.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9bd38652fa6c1c240da7076c0713ca6785efde1d9717e314745cd6935feb5bf0"

  strings:
    $s1 = "%Mike%" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}