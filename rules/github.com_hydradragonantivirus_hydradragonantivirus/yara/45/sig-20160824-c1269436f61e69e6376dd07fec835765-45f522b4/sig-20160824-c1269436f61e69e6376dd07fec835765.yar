rule sig_20160824_c1269436f61e69e6376dd07fec835765 {
  meta:
    description = "datamaliciousorder - file 20160824_c1269436f61e69e6376dd07fec835765.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4bd73d32e8214f81f05ca3d6068a1e170b286b08dfcf2ec006efe672e0a43f6"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}