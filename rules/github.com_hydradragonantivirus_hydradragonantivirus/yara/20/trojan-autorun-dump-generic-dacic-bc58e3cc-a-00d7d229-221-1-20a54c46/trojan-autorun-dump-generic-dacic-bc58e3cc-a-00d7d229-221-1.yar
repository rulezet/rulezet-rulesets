rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_221_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_221_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a87b2a0df8db1b059afe1bfd1fc06a667af6b33ae77a40c16fba8745b9a0ec3a"

  strings:
    $s1 = "bhmust be a Qualified Educational User to use soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}