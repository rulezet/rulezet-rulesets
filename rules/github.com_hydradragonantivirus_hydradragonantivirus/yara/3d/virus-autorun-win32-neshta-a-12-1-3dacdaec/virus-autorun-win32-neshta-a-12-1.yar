rule Virus_Autorun_Win32_Neshta_A_12_1 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c8b04df2e6d96d99252f33834b1044ea9d1f8b1f29ab13fedc12fb80a8c967dc"

  strings:
    $s1 = "TRap?<RRRRn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}