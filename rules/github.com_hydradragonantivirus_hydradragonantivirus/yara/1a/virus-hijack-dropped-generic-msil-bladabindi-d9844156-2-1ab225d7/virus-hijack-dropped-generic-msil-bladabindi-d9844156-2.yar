rule Virus_Hijack_Dropped_Generic_MSIL_Bladabindi_D9844156_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Generic.MSIL.Bladabindi.D9844156_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "960669d6d8180adfc2c060d6aa40d674b91afee394a433425b9a51a922ba2b55"

  strings:
    $s1 = "HotI*V" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}