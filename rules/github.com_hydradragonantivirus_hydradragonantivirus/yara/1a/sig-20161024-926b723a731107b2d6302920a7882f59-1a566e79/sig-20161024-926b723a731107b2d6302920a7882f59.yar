rule sig_20161024_926b723a731107b2d6302920a7882f59 {
  meta:
    description = "datamaliciousorder - file 20161024_926b723a731107b2d6302920a7882f59.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a04dacaa10760a175b93733400f5505144876694c20888f3ee24783b63bd2086"

  strings:
    $s1 = "} while (xi++ < il);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}