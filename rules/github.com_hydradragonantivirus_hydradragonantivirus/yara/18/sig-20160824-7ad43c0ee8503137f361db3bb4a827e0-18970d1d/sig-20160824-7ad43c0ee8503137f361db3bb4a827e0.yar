rule sig_20160824_7ad43c0ee8503137f361db3bb4a827e0 {
  meta:
    description = "datamaliciousorder - file 20160824_7ad43c0ee8503137f361db3bb4a827e0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3030f552993e4590c35c12147cd1869da7e9272351443d60040cd7b9b6f3656"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}