rule sig_20160823_8aa4ea236d9f80659545cac4bb7e90f6 {
  meta:
    description = "datamaliciousorder - file 20160823_8aa4ea236d9f80659545cac4bb7e90f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5fc90d22decc726cd8f2cba3a2701569965b5d4eb1dcacefd8a83904a41834e"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}