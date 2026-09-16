rule sig_20160823_b78a6e8bea15e55c21045062afb01179 {
  meta:
    description = "datamaliciousorder - file 20160823_b78a6e8bea15e55c21045062afb01179.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ddd193f2985892e0fb1298000cda5adf5511afb237a9601cd03314c1e919e7db"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}