rule sig_20160824_4c0eb13ae8281e64d869e831fa9de030 {
  meta:
    description = "datamaliciousorder - file 20160824_4c0eb13ae8281e64d869e831fa9de030.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "302502c5789eb71543a4da27844c5a403af4beb118b09ca7e98487d27d424280"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}