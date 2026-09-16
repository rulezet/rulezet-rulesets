rule sig_20160823_c8bb711f17c1af63d6c64204d2de26e0 {
  meta:
    description = "datamaliciousorder - file 20160823_c8bb711f17c1af63d6c64204d2de26e0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "806b377edfa8f3e55c84a6f2f6c47a21f352d64d33f61461feb0724882efdd6d"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}