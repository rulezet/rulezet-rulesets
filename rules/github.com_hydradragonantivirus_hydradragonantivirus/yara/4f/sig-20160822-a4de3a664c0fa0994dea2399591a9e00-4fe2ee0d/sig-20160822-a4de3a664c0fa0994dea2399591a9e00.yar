rule sig_20160822_a4de3a664c0fa0994dea2399591a9e00 {
  meta:
    description = "datamaliciousorder - file 20160822_a4de3a664c0fa0994dea2399591a9e00.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64ea7155937be8d161b49f35d5946e56c0a1957dd4f5aff231dbd0e62a1e38d5"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}