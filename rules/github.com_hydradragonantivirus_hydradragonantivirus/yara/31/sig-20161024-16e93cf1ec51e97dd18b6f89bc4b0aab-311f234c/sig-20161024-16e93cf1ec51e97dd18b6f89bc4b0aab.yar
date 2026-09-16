rule sig_20161024_16e93cf1ec51e97dd18b6f89bc4b0aab {
  meta:
    description = "datamaliciousorder - file 20161024_16e93cf1ec51e97dd18b6f89bc4b0aab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "054664bd9d344cfe9e73e576a3f22f32f32458619e3f1d4eead6fcea6f70faee"

  strings:
    $s1 = "} while (np++ < ex);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}