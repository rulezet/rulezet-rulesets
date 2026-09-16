rule sig_20160823_ffa4d8e36c793631f1f138914294c6dc {
  meta:
    description = "datamaliciousorder - file 20160823_ffa4d8e36c793631f1f138914294c6dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85581ef28da4155ab20659716d28492e4c32fbc3894362ce82c3e5b3d5a61950"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}