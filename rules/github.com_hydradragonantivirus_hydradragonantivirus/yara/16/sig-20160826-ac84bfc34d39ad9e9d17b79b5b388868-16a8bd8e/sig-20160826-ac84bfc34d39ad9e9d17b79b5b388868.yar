rule sig_20160826_ac84bfc34d39ad9e9d17b79b5b388868 {
  meta:
    description = "datamaliciousorder - file 20160826_ac84bfc34d39ad9e9d17b79b5b388868.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc6f6d59c0822726b79b4fbc6da8b74922ae4aa726bf10995b2e03cc2cd06918"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}