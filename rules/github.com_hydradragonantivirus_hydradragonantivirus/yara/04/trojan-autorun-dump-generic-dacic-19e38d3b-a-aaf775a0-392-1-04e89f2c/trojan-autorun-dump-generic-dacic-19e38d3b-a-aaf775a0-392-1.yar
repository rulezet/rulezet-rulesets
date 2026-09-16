rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_392_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_392_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce38f0efaebebb9218b215a94e61ae4f03f5b89045b1a385e4ee0585aa46d307"

  strings:
    $s1 = "]posted a" fullword ascii
    $s2 = "qUAG<OU" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}