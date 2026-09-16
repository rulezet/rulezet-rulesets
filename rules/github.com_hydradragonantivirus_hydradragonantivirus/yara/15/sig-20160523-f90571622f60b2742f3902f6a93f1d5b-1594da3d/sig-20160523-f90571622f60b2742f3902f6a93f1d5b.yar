rule sig_20160523_f90571622f60b2742f3902f6a93f1d5b {
  meta:
    description = "datamaliciousorder - file 20160523_f90571622f60b2742f3902f6a93f1d5b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e625048a2f98710616a880edef90244b0e43b35e15feb7abcdf892d4348c2191"

  strings:
    $s1 = "verse().join('');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}