rule sig_20160822_85836752a9e04c5aacb45208e25207ec {
  meta:
    description = "datamaliciousorder - file 20160822_85836752a9e04c5aacb45208e25207ec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9040ddc03893a266ce4c55f62fa2015638bb1846363fb831487058dca02d44a4"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}