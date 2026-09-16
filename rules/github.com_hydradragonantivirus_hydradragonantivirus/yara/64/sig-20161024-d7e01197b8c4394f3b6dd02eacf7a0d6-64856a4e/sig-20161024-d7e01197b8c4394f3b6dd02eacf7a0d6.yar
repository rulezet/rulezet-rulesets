rule sig_20161024_d7e01197b8c4394f3b6dd02eacf7a0d6 {
  meta:
    description = "datamaliciousorder - file 20161024_d7e01197b8c4394f3b6dd02eacf7a0d6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c39390b6a10db2e7f0d02e6d5ac423abf3bb0f1b5d8cfabdce6a1a9e6ef2e5e3"

  strings:
    $s1 = "} while (yu++ < ak0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}