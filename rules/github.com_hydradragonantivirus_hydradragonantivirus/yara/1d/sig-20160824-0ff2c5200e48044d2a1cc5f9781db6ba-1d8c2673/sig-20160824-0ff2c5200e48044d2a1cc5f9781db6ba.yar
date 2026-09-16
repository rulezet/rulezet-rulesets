rule sig_20160824_0ff2c5200e48044d2a1cc5f9781db6ba {
  meta:
    description = "datamaliciousorder - file 20160824_0ff2c5200e48044d2a1cc5f9781db6ba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be7af4c229fcab455dffcf113b6a076bdf85475036e1d1e2d424efe0d3d5047a"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}