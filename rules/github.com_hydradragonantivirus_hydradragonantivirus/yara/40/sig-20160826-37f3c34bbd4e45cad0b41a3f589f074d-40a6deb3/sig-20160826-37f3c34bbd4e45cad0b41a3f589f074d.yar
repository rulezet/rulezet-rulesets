rule sig_20160826_37f3c34bbd4e45cad0b41a3f589f074d {
  meta:
    description = "datamaliciousorder - file 20160826_37f3c34bbd4e45cad0b41a3f589f074d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "16f97e272c0da20a643526e9ce264358a263b524d2c8eda0a6efe447f2310f5d"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}