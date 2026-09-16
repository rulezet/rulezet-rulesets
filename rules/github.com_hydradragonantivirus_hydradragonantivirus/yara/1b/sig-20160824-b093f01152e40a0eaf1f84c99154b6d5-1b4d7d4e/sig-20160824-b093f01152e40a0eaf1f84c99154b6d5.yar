rule sig_20160824_b093f01152e40a0eaf1f84c99154b6d5 {
  meta:
    description = "datamaliciousorder - file 20160824_b093f01152e40a0eaf1f84c99154b6d5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "061995464d96881b7df78bc4407a262a55a9153ffd8d34022348752b5b0ecf0f"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}