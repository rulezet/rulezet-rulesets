rule sig_20160826_97dd8ff4b8460feaf54f751fb7b7aad0 {
  meta:
    description = "datamaliciousorder - file 20160826_97dd8ff4b8460feaf54f751fb7b7aad0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08950078356efbb22de414472eb7c6149917b33d16d4e6dfccb9084ef8dd2b52"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}