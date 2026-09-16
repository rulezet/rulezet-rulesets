rule sig_20160826_384d76f5b1abd9a15c7b520df3b3b56b {
  meta:
    description = "datamaliciousorder - file 20160826_384d76f5b1abd9a15c7b520df3b3b56b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef6c165b5e9a204190e8cfece49e99802fafe84d324b5d8f692bddb14b2262e3"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}