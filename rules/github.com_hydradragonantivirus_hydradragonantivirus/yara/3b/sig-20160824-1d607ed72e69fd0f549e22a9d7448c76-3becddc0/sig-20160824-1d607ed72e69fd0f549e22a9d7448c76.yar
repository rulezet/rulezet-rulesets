rule sig_20160824_1d607ed72e69fd0f549e22a9d7448c76 {
  meta:
    description = "datamaliciousorder - file 20160824_1d607ed72e69fd0f549e22a9d7448c76.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6be9e70e4f9bf2467e0b574b7e0cdc93d26522b75ac1b310b522a8f4897c0548"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}