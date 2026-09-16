rule sig_20160823_d2f049b00e16250c9c61b288ac8cae17 {
  meta:
    description = "datamaliciousorder - file 20160823_d2f049b00e16250c9c61b288ac8cae17.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "035e30d3748a2f80a981b3978a13f7c3b614310a50187f13d316899020c990f0"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}