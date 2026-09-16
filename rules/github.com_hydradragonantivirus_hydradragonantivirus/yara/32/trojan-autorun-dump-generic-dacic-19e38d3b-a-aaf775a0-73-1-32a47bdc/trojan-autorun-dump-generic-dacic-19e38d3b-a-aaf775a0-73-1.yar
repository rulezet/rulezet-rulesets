rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_73_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_73_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c70bcc3f72509d00300566ad5ea67288cad74ff9be50c5a3728b4d6db022126c"

  strings:
    $s1 = "3are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}