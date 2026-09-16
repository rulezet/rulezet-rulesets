rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aian2n_29_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_29_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db874f432a29e4ef462ce3c49c3ce21653ca5e6fd3c88d62f1f1bed9d6d046df"

  strings:
    $s1 = "D(format != NULL)" fullword wide
    $s2 = "OW%rEIn" fullword ascii
    $s3 = "M RiER" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}