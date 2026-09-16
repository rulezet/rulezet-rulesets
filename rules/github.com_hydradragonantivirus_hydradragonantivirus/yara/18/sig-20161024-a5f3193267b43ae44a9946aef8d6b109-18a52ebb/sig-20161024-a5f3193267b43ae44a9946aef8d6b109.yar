rule sig_20161024_a5f3193267b43ae44a9946aef8d6b109 {
  meta:
    description = "datamaliciousorder - file 20161024_a5f3193267b43ae44a9946aef8d6b109.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce0105f16128865b39247472c2a550328f94aa8b3db5fa10e77880aa9ff81b77"

  strings:
    $s1 = "} while (ki++ < vr);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}