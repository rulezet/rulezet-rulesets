rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_672_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_672_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "229603c268fd1bef674ec5fa33fe868e0336143ecb50ef1e320c3a8f3fcc8c6a"

  strings:
    $s1 = "!Oracle does not warrant that the Oracle Universi" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}