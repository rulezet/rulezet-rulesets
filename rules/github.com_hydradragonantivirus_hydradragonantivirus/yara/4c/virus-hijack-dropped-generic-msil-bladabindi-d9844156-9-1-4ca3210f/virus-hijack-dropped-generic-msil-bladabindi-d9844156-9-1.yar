rule Virus_Hijack_Dropped_Generic_MSIL_Bladabindi_D9844156_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Generic.MSIL.Bladabindi.D9844156_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c805a3c197124a4b787e98952c88aa78c98a6f36a8abea73dd2a9a4ff1b89948"

  strings:
    $s1 = "Allo5ation too large or negative: %u bytes." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}