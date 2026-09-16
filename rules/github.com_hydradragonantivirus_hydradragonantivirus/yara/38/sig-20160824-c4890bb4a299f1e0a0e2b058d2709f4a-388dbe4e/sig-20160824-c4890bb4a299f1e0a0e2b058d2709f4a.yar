rule sig_20160824_c4890bb4a299f1e0a0e2b058d2709f4a {
  meta:
    description = "datamaliciousorder - file 20160824_c4890bb4a299f1e0a0e2b058d2709f4a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b1d29f26a96bdabb3c7dff8fe7439fbb7266f5f3d92ac6a80796add99c221f32"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}