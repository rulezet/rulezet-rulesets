rule sig_20160824_41d4321ca12021f8e06e8d86705d8666 {
  meta:
    description = "datamaliciousorder - file 20160824_41d4321ca12021f8e06e8d86705d8666.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe3a00b999b17326dd083ad34eb596ed6f1aac7527e334f77b630583b8d1df19"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}