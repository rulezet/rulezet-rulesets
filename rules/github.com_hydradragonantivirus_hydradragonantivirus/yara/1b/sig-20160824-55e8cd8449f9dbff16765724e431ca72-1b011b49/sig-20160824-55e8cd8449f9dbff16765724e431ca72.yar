rule sig_20160824_55e8cd8449f9dbff16765724e431ca72 {
  meta:
    description = "datamaliciousorder - file 20160824_55e8cd8449f9dbff16765724e431ca72.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59262d8e71ed08bedb209232b2954a56ce45597f53a6880f9ad90078145267db"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}