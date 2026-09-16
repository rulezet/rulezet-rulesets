rule sig_20161024_6d778f05012bad1b1343bcc968da2865 {
  meta:
    description = "datamaliciousorder - file 20161024_6d778f05012bad1b1343bcc968da2865.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f13ca880cdf37b46b19cb30c733d5549834387133d8c1e526abc0e4603dac35"

  strings:
    $s1 = "} while (xq++ < em);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}