rule sig_20160822_a021e1ddf85c19a2355e0bcc5d687ad2 {
  meta:
    description = "datamaliciousorder - file 20160822_a021e1ddf85c19a2355e0bcc5d687ad2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97b107a375da5bf591e7e598b63f548f7ec384c8f37eab2542f9e688f57ff234"

  strings:
    $s1 = "var UGc3 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}