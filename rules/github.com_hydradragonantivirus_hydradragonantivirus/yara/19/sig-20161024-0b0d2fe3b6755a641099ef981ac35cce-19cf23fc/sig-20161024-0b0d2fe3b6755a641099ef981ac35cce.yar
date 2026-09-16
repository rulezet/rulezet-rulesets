rule sig_20161024_0b0d2fe3b6755a641099ef981ac35cce {
  meta:
    description = "datamaliciousorder - file 20161024_0b0d2fe3b6755a641099ef981ac35cce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97a81e0a6b450630d510a461878435f3144799e11be0ba0baeaafefc9f8af862"

  strings:
    $s1 = "} while (op++ < ju);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}