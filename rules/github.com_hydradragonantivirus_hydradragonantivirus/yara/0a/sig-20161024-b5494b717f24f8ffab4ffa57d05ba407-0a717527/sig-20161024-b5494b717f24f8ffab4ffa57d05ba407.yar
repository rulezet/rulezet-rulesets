rule sig_20161024_b5494b717f24f8ffab4ffa57d05ba407 {
  meta:
    description = "datamaliciousorder - file 20161024_b5494b717f24f8ffab4ffa57d05ba407.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "48cdcef88964d6d414d6dad320e6fe91b9f3879d363b142bd5f9abb92ded1a2f"

  strings:
    $s1 = "} while (px++ < tq);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}