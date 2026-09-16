rule sig_20161024_fbe2517267b6823c353f86b0623c8d64 {
  meta:
    description = "datamaliciousorder - file 20161024_fbe2517267b6823c353f86b0623c8d64.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28dd46abb1180e18d957a6ce0fdc8ccc31a637fcc96814a75911351b44f52c06"

  strings:
    $s1 = "} while (kf++ < oj);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}