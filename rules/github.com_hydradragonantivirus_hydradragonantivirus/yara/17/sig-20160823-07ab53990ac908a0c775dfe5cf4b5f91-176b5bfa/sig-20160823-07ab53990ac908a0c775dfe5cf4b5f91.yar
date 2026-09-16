rule sig_20160823_07ab53990ac908a0c775dfe5cf4b5f91 {
  meta:
    description = "datamaliciousorder - file 20160823_07ab53990ac908a0c775dfe5cf4b5f91.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58bd57d13a6295dab0878860f48b87a6b2d474bfd546ec9aa252fb2062c05c39"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}