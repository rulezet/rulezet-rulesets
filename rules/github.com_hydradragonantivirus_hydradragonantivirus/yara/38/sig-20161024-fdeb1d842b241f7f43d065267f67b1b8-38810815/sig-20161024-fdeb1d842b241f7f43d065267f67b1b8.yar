rule sig_20161024_fdeb1d842b241f7f43d065267f67b1b8 {
  meta:
    description = "datamaliciousorder - file 20161024_fdeb1d842b241f7f43d065267f67b1b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c73881dee1107e8aac24602863d8ac52f784c762cb29523c5d42d224b64f8a7a"

  strings:
    $s1 = "} while (du++ < vq);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}