rule sig_20160823_041bb7585d6e6045300913d88f2a2d43 {
  meta:
    description = "datamaliciousorder - file 20160823_041bb7585d6e6045300913d88f2a2d43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4da0014608f101b45eef8b05ebed64606609181b2563fa5314ca4ebe46d8fd47"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}