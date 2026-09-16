rule sig_20160826_7ad9c6ae70beb6d2ef9718a96f7233a9 {
  meta:
    description = "datamaliciousorder - file 20160826_7ad9c6ae70beb6d2ef9718a96f7233a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1533fa88b975d1ea53d8bfe85b7d84448b6b232c1c0d976ac282682ae1b39db9"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}