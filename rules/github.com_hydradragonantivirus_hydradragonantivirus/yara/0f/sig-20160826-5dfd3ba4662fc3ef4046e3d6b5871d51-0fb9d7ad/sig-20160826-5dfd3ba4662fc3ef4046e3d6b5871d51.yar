rule sig_20160826_5dfd3ba4662fc3ef4046e3d6b5871d51 {
  meta:
    description = "datamaliciousorder - file 20160826_5dfd3ba4662fc3ef4046e3d6b5871d51.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b69ba98669985af00ad7260b687d290dd83821a9968cbaca9036093f4b5d58ac"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}