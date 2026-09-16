rule sig_20161024_4cf63d5969de2e88538d6f73f2cea1d5 {
  meta:
    description = "datamaliciousorder - file 20161024_4cf63d5969de2e88538d6f73f2cea1d5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5647eca9d2b0fb4e84248a43ae9b7bf72865827e41393f4e1ca8331899f1f6e5"

  strings:
    $s1 = "} while (wl++ < vm);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}