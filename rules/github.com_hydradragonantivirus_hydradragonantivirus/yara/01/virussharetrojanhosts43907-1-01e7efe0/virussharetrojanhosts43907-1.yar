rule VirusShareTrojanHosts43907_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanHosts43907_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a8b1eae1acaa4aa33a48694c404d80dce985ee5953d98a70644a0efb4df9570"

  strings:
    $s1 = "dg3ypDAonQcOidMs0w.WP6RZJql8gZrNhVA9v+RJDcsuMfOxrTCYImPe+iGR41459RDH4FvPdNk`1[[System.Object, mscorlib, Version=4.0.0.0, Culture" ascii
    $s2 = "<Module>{AC81E6A6-CD50-45A0-863D-F09665F386A1}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}