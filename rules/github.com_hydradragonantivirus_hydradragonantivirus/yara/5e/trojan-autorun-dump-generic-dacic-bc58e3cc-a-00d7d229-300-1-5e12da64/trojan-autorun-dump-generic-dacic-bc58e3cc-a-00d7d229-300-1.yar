rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_300_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_300_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0438ec5590416b2f804d13941bcfc5402ba148887e91435354c04616482603cd"

  strings:
    $s1 = "4are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}