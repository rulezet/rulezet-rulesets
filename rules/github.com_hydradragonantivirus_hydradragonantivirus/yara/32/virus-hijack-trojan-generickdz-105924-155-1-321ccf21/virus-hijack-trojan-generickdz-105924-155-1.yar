rule Virus_Hijack_Trojan_GenericKDZ_105924_155_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_155_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c641bb825f08a77bd713f0e9cf0c8114b7aefba8c423053fc4d52e401142349d"

  strings:
    $s1 = "dg3ypDAonQcOidMs0w.WP6RZJql8gZrNhVA9v+RJDcsuMfOxrTCYImPe+iGR41459RDH4FvPdNk`1[[System.Object, mscorlib, Version=4.0.0.0, Culture" ascii
    $s2 = "<Module>{EF6F17D5-401F-4ABC-ACBD-C08073064786}" fullword ascii
    $s3 = "9Rl>biCe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}