rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_274_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_274_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01f6cb222552c7de5a822017d9979103aea06847d186234c8aa4e085fcc16d48"

  strings:
    $s1 = "Giz kodota tiziwibumap<Pegis lul jefimiwifeyopud remosacuhuyige cimeganoregiwu cuya" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}