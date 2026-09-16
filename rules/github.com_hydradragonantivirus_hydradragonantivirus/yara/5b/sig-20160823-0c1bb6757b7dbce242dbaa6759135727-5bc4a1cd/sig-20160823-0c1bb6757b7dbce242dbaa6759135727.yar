rule sig_20160823_0c1bb6757b7dbce242dbaa6759135727 {
  meta:
    description = "datamaliciousorder - file 20160823_0c1bb6757b7dbce242dbaa6759135727.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e5007903284082e2652d3a2ad0afe718caa622678c58661252b5b6a91f401b4"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}