rule sig_20160824_4b348fccfcb5641432127204d1eaa18d {
  meta:
    description = "datamaliciousorder - file 20160824_4b348fccfcb5641432127204d1eaa18d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7d9b24d6ef7fb204917db2e6ee084573ebabe671e6aa0b946a03ae9e8aed17f"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}