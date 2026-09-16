rule sig_20161024_0db369a7c776659b311b6a670d0adf4c {
  meta:
    description = "datamaliciousorder - file 20161024_0db369a7c776659b311b6a670d0adf4c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6f7785cc0eba22b13c2d659bdf3e20140ced30dfded00483f2e5e48ebef475d"

  strings:
    $s1 = "} while (ql++ < yd);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}