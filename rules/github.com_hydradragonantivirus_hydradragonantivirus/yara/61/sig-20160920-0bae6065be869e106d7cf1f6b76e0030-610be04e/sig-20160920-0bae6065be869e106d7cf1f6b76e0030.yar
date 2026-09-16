rule sig_20160920_0bae6065be869e106d7cf1f6b76e0030 {
  meta:
    description = "datamaliciousorder - file 20160920_0bae6065be869e106d7cf1f6b76e0030.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad3efe74232d9fb693a496a8e9816621bf21cb57f3a0418e4fd99cbae60e69e4"

  strings:
    $s1 = "split('msemse');" fullword ascii

  condition:
    uint16(0) == 0x2f0a and
    all of them
}