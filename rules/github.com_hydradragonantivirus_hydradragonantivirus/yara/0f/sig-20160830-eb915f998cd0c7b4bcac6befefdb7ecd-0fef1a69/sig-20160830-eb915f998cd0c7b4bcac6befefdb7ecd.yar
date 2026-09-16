rule sig_20160830_eb915f998cd0c7b4bcac6befefdb7ecd {
  meta:
    description = "datamaliciousorder - file 20160830_eb915f998cd0c7b4bcac6befefdb7ecd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3540d7d8b64e11835475ee085d4f2852b94e43010a6a9c64edd1b61b1cc3a56"

  strings:
    $s1 = "split(\" \");" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}