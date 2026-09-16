rule sig_20170331_3e38dd52734be11f4c47ab5128f493be {
  meta:
    description = "datamaliciousorder - file 20170331_3e38dd52734be11f4c47ab5128f493be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11dae8669131ba7456ff188761f4ed082e1ee20010475518d4417ebb13d24898"

  strings:
    $s1 = "while(tersa < 10){tersa++;}" fullword ascii

  condition:
    uint16(0) == 0x6574 and
    all of them
}