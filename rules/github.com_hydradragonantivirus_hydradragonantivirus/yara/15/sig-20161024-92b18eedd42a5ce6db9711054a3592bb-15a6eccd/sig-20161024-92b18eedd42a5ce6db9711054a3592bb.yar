rule sig_20161024_92b18eedd42a5ce6db9711054a3592bb {
  meta:
    description = "datamaliciousorder - file 20161024_92b18eedd42a5ce6db9711054a3592bb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f9fbada3c6158a63bd424b0750528be929b833c50f843870f816fd1a5a06af8"

  strings:
    $s1 = "} while (ui++ < as0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}