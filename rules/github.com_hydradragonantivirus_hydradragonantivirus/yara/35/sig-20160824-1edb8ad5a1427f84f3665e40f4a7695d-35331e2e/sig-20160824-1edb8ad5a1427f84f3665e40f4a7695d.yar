rule sig_20160824_1edb8ad5a1427f84f3665e40f4a7695d {
  meta:
    description = "datamaliciousorder - file 20160824_1edb8ad5a1427f84f3665e40f4a7695d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f4c2111849453c4a7260cb2e94076c79cc8818c6a1a268b04929af1266bf5e1"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}