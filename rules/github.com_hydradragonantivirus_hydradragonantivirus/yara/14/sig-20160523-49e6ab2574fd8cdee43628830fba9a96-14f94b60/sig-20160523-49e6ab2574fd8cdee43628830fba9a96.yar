rule sig_20160523_49e6ab2574fd8cdee43628830fba9a96 {
  meta:
    description = "datamaliciousorder - file 20160523_49e6ab2574fd8cdee43628830fba9a96.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b8e53c150f036d1abf8e3ae09603f9e57198c907bfc5c80a77a95926e86707b2"

  strings:
    $s1 = "join('');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}