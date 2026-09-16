rule sig_20161024_0aa1d37a3ca48fb3f9170b1e5fdcd0c4 {
  meta:
    description = "datamaliciousorder - file 20161024_0aa1d37a3ca48fb3f9170b1e5fdcd0c4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea40349157111129bc1345a9fb801edaaaca2530f893bc7be10d104391cc6b13"

  strings:
    $s1 = "} while (zr++ < hv);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}