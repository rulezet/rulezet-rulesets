rule sig_20161024_0f7dde2eb153e5075d1819e095d52f9d {
  meta:
    description = "datamaliciousorder - file 20161024_0f7dde2eb153e5075d1819e095d52f9d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "993c020ef9fe2faed3182e3fcc3aa224e76b92ab148f56b13eb26ee50688970f"

  strings:
    $s1 = "} while (ca++ < xl);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}