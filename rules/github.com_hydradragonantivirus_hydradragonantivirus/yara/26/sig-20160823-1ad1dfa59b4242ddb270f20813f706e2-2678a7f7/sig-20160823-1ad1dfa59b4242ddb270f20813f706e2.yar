rule sig_20160823_1ad1dfa59b4242ddb270f20813f706e2 {
  meta:
    description = "datamaliciousorder - file 20160823_1ad1dfa59b4242ddb270f20813f706e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba62a77a7f8cdb588f2030f68e6e99ad3dce07ade579349639e1b1757d1c50e3"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}