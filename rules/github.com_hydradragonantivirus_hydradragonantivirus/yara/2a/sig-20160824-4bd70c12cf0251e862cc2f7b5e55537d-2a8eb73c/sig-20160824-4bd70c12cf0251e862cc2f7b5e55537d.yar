rule sig_20160824_4bd70c12cf0251e862cc2f7b5e55537d {
  meta:
    description = "datamaliciousorder - file 20160824_4bd70c12cf0251e862cc2f7b5e55537d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc95b73666f4b3ca7903a1d0cb53b32b6a93e21540567fcdfe718fa3fea8b9cd"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}