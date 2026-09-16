rule sig_20161024_ed5a087fb40a13277d9aa0a8c0b4b15a {
  meta:
    description = "datamaliciousorder - file 20161024_ed5a087fb40a13277d9aa0a8c0b4b15a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f198118bdfdcaf3ea5125ec35eb30644ad12ed2a3125718a163667bb49701324"

  strings:
    $s1 = "} while (yk++ < eq0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}