rule sig_20160823_248561b0d36c3a30d3b7dda4587f7322 {
  meta:
    description = "datamaliciousorder - file 20160823_248561b0d36c3a30d3b7dda4587f7322.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ec765dc40d1cba4750d9b2e8796ec70f5edec1c8c77a6725ce3dd8bdcaafc7b"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}