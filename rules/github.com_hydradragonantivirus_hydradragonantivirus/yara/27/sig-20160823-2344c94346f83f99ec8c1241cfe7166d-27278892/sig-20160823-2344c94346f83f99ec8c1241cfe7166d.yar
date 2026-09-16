rule sig_20160823_2344c94346f83f99ec8c1241cfe7166d {
  meta:
    description = "datamaliciousorder - file 20160823_2344c94346f83f99ec8c1241cfe7166d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd27b3e09783642d418e4c5455ca47ab317f4dcac6b1ee70aa3c78a402574035"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}