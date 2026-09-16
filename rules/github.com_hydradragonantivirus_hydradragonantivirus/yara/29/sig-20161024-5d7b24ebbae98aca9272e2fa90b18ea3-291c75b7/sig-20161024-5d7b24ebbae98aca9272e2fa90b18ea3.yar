rule sig_20161024_5d7b24ebbae98aca9272e2fa90b18ea3 {
  meta:
    description = "datamaliciousorder - file 20161024_5d7b24ebbae98aca9272e2fa90b18ea3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d016c7fb9790e6dfacba53cf2ee3508452970a07edc2ab6df56c1bc1aa80ad90"

  strings:
    $s1 = "} while (rr0++ < jr0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}