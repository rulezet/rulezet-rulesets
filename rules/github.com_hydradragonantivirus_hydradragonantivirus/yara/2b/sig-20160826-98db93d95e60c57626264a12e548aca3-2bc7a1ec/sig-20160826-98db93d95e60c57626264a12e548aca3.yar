rule sig_20160826_98db93d95e60c57626264a12e548aca3 {
  meta:
    description = "datamaliciousorder - file 20160826_98db93d95e60c57626264a12e548aca3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d919ed998f12a7f622610e7ffcb0fdb9ebe3cf12eddf39537b1e682aa895148c"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4f\",\"\\x6a\",\"\\x3d\",\"\\x22\",\"\\x73\",\"\\x65" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}