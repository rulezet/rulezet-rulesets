rule sig_20160823_62a475b347c40872c2f2e29f10dddd45 {
  meta:
    description = "datamaliciousorder - file 20160823_62a475b347c40872c2f2e29f10dddd45.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "000f86dedcd262edead9dfa392aa70354761e5a69c2e0157ea4faeeda6989365"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}