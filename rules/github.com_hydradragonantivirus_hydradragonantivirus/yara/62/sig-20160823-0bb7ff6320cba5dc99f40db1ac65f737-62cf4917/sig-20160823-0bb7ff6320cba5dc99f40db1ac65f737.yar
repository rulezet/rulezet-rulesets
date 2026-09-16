rule sig_20160823_0bb7ff6320cba5dc99f40db1ac65f737 {
  meta:
    description = "datamaliciousorder - file 20160823_0bb7ff6320cba5dc99f40db1ac65f737.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f5e9c8e1eb737dc61bb4474d239ea2d6a40d3d2e11b75c50ed7ed35c0ec7c95"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}