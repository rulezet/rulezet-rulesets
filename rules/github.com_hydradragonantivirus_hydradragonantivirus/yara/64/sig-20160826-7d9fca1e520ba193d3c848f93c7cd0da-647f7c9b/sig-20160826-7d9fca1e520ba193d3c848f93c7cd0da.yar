rule sig_20160826_7d9fca1e520ba193d3c848f93c7cd0da {
  meta:
    description = "datamaliciousorder - file 20160826_7d9fca1e520ba193d3c848f93c7cd0da.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d151998fca4066c1872f62d60602819c06ec8756b4745d932523396fbf5e5583"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}