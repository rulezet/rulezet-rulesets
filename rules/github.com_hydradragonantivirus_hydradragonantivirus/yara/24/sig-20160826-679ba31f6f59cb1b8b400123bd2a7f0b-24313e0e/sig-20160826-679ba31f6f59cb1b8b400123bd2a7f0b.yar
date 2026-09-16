rule sig_20160826_679ba31f6f59cb1b8b400123bd2a7f0b {
  meta:
    description = "datamaliciousorder - file 20160826_679ba31f6f59cb1b8b400123bd2a7f0b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e720d79923c0e0854d31172b4169b434bec6a83a2fff9d3d7d72cadd629b00d2"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}