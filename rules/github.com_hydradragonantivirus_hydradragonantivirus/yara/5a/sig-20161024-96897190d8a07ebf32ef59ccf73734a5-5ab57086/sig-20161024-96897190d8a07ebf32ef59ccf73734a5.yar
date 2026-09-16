rule sig_20161024_96897190d8a07ebf32ef59ccf73734a5 {
  meta:
    description = "datamaliciousorder - file 20161024_96897190d8a07ebf32ef59ccf73734a5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38f8e4720ad9fbf7c384567dc317e01a827370fe24f55c98a236bbc8239ba6ec"

  strings:
    $s1 = "} while (gq++ < au);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}