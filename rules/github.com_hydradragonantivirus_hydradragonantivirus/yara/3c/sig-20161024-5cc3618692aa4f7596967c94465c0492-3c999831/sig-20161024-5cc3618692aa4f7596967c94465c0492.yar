rule sig_20161024_5cc3618692aa4f7596967c94465c0492 {
  meta:
    description = "datamaliciousorder - file 20161024_5cc3618692aa4f7596967c94465c0492.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79738a2a42e83a16d937e21ad31ac287a76507d973e8b6cf373f4c17e61d07fa"

  strings:
    $s1 = "} while (zf++ < ii);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}