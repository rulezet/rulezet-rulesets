rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_788_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_788_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "952ef0208edf73d7a2f7ecc03f5f839ac6a40bfc38117452db4717a704cd20f8"

  strings:
    $s1 = "8create this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}