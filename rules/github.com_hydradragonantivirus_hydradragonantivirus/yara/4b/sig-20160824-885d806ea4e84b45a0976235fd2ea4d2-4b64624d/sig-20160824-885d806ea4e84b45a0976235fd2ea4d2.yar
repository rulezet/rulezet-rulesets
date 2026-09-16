rule sig_20160824_885d806ea4e84b45a0976235fd2ea4d2 {
  meta:
    description = "datamaliciousorder - file 20160824_885d806ea4e84b45a0976235fd2ea4d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94fe5d3b11f44a454d19b2981d7617d348f611a1240a771de0ae596637965cb7"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}