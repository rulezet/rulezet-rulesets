rule sig_20160823_3302046bfa9b0e97a8baa33ef9fb5703 {
  meta:
    description = "datamaliciousorder - file 20160823_3302046bfa9b0e97a8baa33ef9fb5703.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1fabec3a64579b1427143334ff872c0f1c5a685804d2160f4a32d6836411a7ab"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}