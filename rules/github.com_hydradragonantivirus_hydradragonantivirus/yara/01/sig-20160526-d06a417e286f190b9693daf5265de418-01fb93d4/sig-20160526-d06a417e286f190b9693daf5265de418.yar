rule sig_20160526_d06a417e286f190b9693daf5265de418 {
  meta:
    description = "datamaliciousorder - file 20160526_d06a417e286f190b9693daf5265de418.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40a1d04021500c4665ae224d05fe52e4b9d43316e839dabeac2cd8d728488c96"

  strings:
    $s1 = "DALE rav\\n\\r;\"gnel\" = nKLDEFZ rav\\n\\r;\"ht\" = 5vUCLDSN rav\\n\\r;\"tgnel\" = 9sQXF rav\\n\\r;\"h\" = 5pYQFWGU rav\\n\\r;" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}