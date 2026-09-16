rule sig_20161024_6a0bb0d5f8717491c31b169b5aa33b74 {
  meta:
    description = "datamaliciousorder - file 20161024_6a0bb0d5f8717491c31b169b5aa33b74.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c46639fb3a1ebc634be3fa0e0f6545707aed6b9c2cfc5e003f1009670dec3f3"

  strings:
    $s1 = "} while (nc++ < ww);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}