rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_68_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_68_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd174583d46e42b79dcb5df8f58c8b87ca9fc051ec2e5ea5c1dd6684aec0c2dd"

  strings:
    $s1 = "/You may temporarily download the fonts to a prin" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}