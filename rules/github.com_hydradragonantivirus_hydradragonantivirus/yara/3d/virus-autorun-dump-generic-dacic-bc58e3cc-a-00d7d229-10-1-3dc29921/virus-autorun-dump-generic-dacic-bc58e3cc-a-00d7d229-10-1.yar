rule Virus_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_10_1 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d729642497b450d77048da4075b4f61d08300df62a76962ac6be78067432d66f"

  strings:
    $s1 = "{z~OS`b[dhOW" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}