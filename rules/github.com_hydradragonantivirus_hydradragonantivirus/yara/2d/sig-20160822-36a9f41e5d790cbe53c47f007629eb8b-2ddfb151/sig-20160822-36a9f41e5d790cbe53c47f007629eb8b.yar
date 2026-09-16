rule sig_20160822_36a9f41e5d790cbe53c47f007629eb8b {
  meta:
    description = "datamaliciousorder - file 20160822_36a9f41e5d790cbe53c47f007629eb8b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11b160d03db7150a129743e92ab97644e000e98f8b859d5af3d6aac9af2369f3"

  strings:
    $s1 = "var UGc3 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}