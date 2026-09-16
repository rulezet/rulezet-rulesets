rule sig_20160824_5eda4b81873403de5550e52f39eba6fc {
  meta:
    description = "datamaliciousorder - file 20160824_5eda4b81873403de5550e52f39eba6fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54c29ac1c59bbdf822c4ff4e6d5350109be68b7c9770099110b41eb2f320e32b"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}