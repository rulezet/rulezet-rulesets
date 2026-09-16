rule sig_20160822_ede13401327377a2541ebf24d3379f86 {
  meta:
    description = "datamaliciousorder - file 20160822_ede13401327377a2541ebf24d3379f86.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86644f87bb80b18c6561994dea861d7c8e292b59a7f6d81ab80cd656d86e257a"

  strings:
    $s1 = "var UGc3 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}