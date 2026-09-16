rule Virus_Hijack_Gen_Trojan_ShellObject_B8Z_ayQY28h_10_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.B8Z@ayQY28h_10_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbc2192b379b09829a74f5c7428d65a8dbff3501b320e8a789ad314a1689a154"

  strings:
    $s1 = "}[<boLL" fullword ascii
    $s2 = "*Niter" fullword ascii
    $s3 = "dIAn]s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}