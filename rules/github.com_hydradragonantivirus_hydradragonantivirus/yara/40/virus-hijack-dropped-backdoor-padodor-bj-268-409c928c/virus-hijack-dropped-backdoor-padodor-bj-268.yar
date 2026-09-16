rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_268 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_268.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "388b982cade2e430e149a5949e0fbdfd8af4bf760ac75a8df3ded168918e75ab"

  strings:
    $s1 = "CISe{AZ&`Cia^`{^Jk8" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}