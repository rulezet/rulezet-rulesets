rule sig_20161024_60a354e73fa06d4f37391644ab9ff458 {
  meta:
    description = "datamaliciousorder - file 20161024_60a354e73fa06d4f37391644ab9ff458.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0bef90774b9629b7b79d8209cd6fae561fd56a8257ce7d810ea5cd5466d3c908"

  strings:
    $s1 = "} while (gn++ < pz);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}