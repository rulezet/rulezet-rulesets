rule sig_20160822_f5304a5f0c523f92768bfc10cb471e8b {
  meta:
    description = "datamaliciousorder - file 20160822_f5304a5f0c523f92768bfc10cb471e8b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98a47c4df846d1459026698f8c4217b759098d6c402df539b373dbed39376b7a"

  strings:
    $s1 = "var UGc3 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}