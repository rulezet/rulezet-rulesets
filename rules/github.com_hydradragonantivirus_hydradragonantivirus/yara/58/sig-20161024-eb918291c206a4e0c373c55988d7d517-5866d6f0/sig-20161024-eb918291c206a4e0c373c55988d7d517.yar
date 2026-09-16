rule sig_20161024_eb918291c206a4e0c373c55988d7d517 {
  meta:
    description = "datamaliciousorder - file 20161024_eb918291c206a4e0c373c55988d7d517.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea3fa86bf8d01ae42a6a6cd3b34e23db76a4c74303f4d6a419aa431a8ed5fee2"

  strings:
    $s1 = "} while (uj++ < jn);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}