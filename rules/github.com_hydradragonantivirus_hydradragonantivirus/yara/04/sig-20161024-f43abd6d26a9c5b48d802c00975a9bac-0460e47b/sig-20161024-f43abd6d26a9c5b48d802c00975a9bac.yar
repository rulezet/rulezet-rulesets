rule sig_20161024_f43abd6d26a9c5b48d802c00975a9bac {
  meta:
    description = "datamaliciousorder - file 20161024_f43abd6d26a9c5b48d802c00975a9bac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7aae9f2c5f20befc41b9ffff1f28c884d83857c4358732ff4973db6b19122661"

  strings:
    $s1 = "} while (et++ < ac);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}