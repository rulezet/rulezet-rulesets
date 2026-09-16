rule sig_20160826_26904e08cfdb81a92aab4b09dfae1307 {
  meta:
    description = "datamaliciousorder - file 20160826_26904e08cfdb81a92aab4b09dfae1307.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bbdb202658ef333d504a61b452742d60603972871968f0afbf5df6aefbad413a"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}