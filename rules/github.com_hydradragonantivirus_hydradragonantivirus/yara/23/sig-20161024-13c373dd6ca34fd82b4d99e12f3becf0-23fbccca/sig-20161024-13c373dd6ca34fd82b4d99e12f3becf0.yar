rule sig_20161024_13c373dd6ca34fd82b4d99e12f3becf0 {
  meta:
    description = "datamaliciousorder - file 20161024_13c373dd6ca34fd82b4d99e12f3becf0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7dc2bec4409cb5a002345a702558b1e58c0cdf68a682e2daed8ea2c6cc36baa"

  strings:
    $s1 = "} while (kr++ < wg);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}