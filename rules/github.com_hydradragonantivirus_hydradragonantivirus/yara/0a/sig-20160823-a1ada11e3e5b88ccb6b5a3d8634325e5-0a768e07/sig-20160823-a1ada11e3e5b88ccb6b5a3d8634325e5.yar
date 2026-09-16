rule sig_20160823_a1ada11e3e5b88ccb6b5a3d8634325e5 {
  meta:
    description = "datamaliciousorder - file 20160823_a1ada11e3e5b88ccb6b5a3d8634325e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5c3a72c4d2b4e9ee2609fb5378eea56381fd489e67eb22f793fe09ebc4d82e6"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}