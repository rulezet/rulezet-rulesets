rule sig_20161024_e060e407f2688f637be9abd7138507bd {
  meta:
    description = "datamaliciousorder - file 20161024_e060e407f2688f637be9abd7138507bd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "202d836daddabc376feafa1a0b035b0b23d8ba3aea8e7cd7243a0c200a16b0c4"

  strings:
    $s1 = "} while (jo++ < xv);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}