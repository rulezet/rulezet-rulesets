rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_19_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_19_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "deb005e193cc1addddc38f34c5db2fae8e3fdce61e1e9790b30abe92ca58a09e"

  strings:
    $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
    $s2 = "leVy&SaV" fullword ascii
    $s3 = "<e<gOla" fullword ascii
    $s4 = "Z[KALO&" fullword ascii
    $s5 = "DaTE`c" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}