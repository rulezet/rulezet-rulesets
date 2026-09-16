rule sig_20161024_74a34105197ceb6c97e566e88951d6b4 {
  meta:
    description = "datamaliciousorder - file 20161024_74a34105197ceb6c97e566e88951d6b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a42ebe7c31da2f47626773a479d4589bdd25d4dd10d13bc10060dd4b046386ca"

  strings:
    $s1 = "} while (az++ < zo);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}