rule sig_20160824_f43f46f26a25b9a902b4442056e39228 {
  meta:
    description = "datamaliciousorder - file 20160824_f43f46f26a25b9a902b4442056e39228.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba001989adc7b821b162d13f2976fb750213c743ccb7ce47e89f703630a2ccd2"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}