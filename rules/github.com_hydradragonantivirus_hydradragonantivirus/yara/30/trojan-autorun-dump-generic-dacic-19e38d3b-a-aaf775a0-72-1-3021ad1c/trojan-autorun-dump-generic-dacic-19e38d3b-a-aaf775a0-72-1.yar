rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_72_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_72_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0923661836d30b9327847d73462c1c6b1fabf583a7fbd5b034d1ade66804e6ee"

  strings:
    $s1 = ")Resource instance not specified, did you call CommonLibraryDllProcessAttach?" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}