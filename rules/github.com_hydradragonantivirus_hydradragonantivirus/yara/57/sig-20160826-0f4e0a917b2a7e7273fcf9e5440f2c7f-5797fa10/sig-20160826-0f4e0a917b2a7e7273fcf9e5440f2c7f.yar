rule sig_20160826_0f4e0a917b2a7e7273fcf9e5440f2c7f {
  meta:
    description = "datamaliciousorder - file 20160826_0f4e0a917b2a7e7273fcf9e5440f2c7f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7538b349a5f80ded3e62bd4a797681e0961437a25c6c6c3f0e021ffadb582c9d"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}