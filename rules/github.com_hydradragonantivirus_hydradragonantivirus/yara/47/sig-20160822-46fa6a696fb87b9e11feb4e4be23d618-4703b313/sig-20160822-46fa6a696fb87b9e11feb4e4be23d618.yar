rule sig_20160822_46fa6a696fb87b9e11feb4e4be23d618 {
  meta:
    description = "datamaliciousorder - file 20160822_46fa6a696fb87b9e11feb4e4be23d618.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e26f1f32582f448f12ed45332afebb2b809ad4abf5d99446de6fdb7a63bedb14"

  strings:
    $s1 = "var UGc3 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}