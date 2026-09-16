rule sig_20161024_9075dc71df639825df467f0d9abd009f {
  meta:
    description = "datamaliciousorder - file 20161024_9075dc71df639825df467f0d9abd009f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96002738370dae7fe033a5a77c1138265340d5f82bd53d421410a42edd637a91"

  strings:
    $s1 = "} while (cn++ < da);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}