rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_715 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_715.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "efeaac2b030d6ff62a94fac9bd2ce567b59f018099b39e2d2f9504432a5b7b69"

  strings:
    $s1 = "wAAr$)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}