rule Virus_Sysbot_Generic_Dacic_Emdup_A_8CFF60C6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Generic.Dacic.Emdup.A.8CFF60C6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42e27e18f6ef88f33c0f96dd19288320619f2a785fbf99db0dbc214833c31b29"

  strings:
    $s1 = "Y*qOPH" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}