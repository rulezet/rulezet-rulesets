rule sig_20160823_a03744676666ea4dd02d609cd539379e {
  meta:
    description = "datamaliciousorder - file 20160823_a03744676666ea4dd02d609cd539379e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4dfbf2abbea1d56f0bc36e2d617d8e7f13d262598f4d71f50d95967dd40892cc"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}