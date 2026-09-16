rule Trojan_Autorun_Generic_Dacic_AAD0835C_A_B2DBC7BA_3 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Generic.Dacic.AAD0835C.A.B2DBC7BA_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0eae15e0cbd645dbf3d1965813b0587000f06382b0d1f8dfb16e7510bc75eb77"

  strings:
    $s1 = "assets, owned or managed for others, which were " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}