rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aK5_lZo_13 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aK5!lZo_13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6fd4d90b3e9eda56e3f77f416311afc23737292d3fd249af70797e4e624a6fb5"

  strings:
    $s1 = "\\My Shared Folder" fullword ascii
    $s2 = "Baga]s" fullword ascii
    $s3 = "`Write" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}