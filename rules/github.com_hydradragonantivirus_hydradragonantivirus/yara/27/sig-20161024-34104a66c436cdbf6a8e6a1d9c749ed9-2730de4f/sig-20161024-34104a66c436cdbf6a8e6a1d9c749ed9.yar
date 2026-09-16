rule sig_20161024_34104a66c436cdbf6a8e6a1d9c749ed9 {
  meta:
    description = "datamaliciousorder - file 20161024_34104a66c436cdbf6a8e6a1d9c749ed9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43efe0d61d38b869b93775560da07dee3d54db601e9f153a5f485dd91d3e0df5"

  strings:
    $s1 = "} while (st++ < uy);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}