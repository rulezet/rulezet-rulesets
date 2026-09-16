rule sig_20160824_da5429acfd2d6e37826ba1afe94ecd32 {
  meta:
    description = "datamaliciousorder - file 20160824_da5429acfd2d6e37826ba1afe94ecd32.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "efc0cccbc8726c3a088d81eaf6fbc6b47ffc347dc6fd3320ac8b0e111c799104"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}