rule sig_20160826_8039fd25b388599aeb731eb906767c1e {
  meta:
    description = "datamaliciousorder - file 20160826_8039fd25b388599aeb731eb906767c1e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b53f1729557fc9c248a65a333a51a4778d9bb323f6a64297a9229fe30887395"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}