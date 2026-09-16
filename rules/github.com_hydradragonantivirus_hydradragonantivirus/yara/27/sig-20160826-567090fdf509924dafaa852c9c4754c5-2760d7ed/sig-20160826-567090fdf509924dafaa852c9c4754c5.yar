rule sig_20160826_567090fdf509924dafaa852c9c4754c5 {
  meta:
    description = "datamaliciousorder - file 20160826_567090fdf509924dafaa852c9c4754c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09ada49c3c90ae99c844c8ff4c33949b96795c211ec75c9daff3d96327f0bbbc"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}