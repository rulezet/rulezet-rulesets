rule sig_20160529_5fe0b26ead885d8008c836633441cc50 {
  meta:
    description = "datamaliciousorder - file 20160529_5fe0b26ead885d8008c836633441cc50.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b38b125a1d4a224cf2055b67f4f6991e13361b376057e0d6ff4be19ccc44d9c2"

  strings:
    $s1 = "reak';                            var v55='bjec';                            var c13='e:\"';                            var g68=" ascii

  condition:
    uint16(0) == 0x3871 and
    all of them
}