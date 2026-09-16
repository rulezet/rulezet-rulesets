rule sig_20160826_3c353afc343a1206a2e6f50bc23ab890 {
  meta:
    description = "datamaliciousorder - file 20160826_3c353afc343a1206a2e6f50bc23ab890.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97bfe44abdd024ac53edd20d8d1351aa110fc9788059bce6529e73827b6c1163"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}