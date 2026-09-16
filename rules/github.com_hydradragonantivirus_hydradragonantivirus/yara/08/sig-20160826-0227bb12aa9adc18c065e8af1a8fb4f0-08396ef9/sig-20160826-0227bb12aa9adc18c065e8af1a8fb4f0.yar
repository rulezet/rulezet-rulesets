rule sig_20160826_0227bb12aa9adc18c065e8af1a8fb4f0 {
  meta:
    description = "datamaliciousorder - file 20160826_0227bb12aa9adc18c065e8af1a8fb4f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c5832eff87428423195dddd76419bc6cc5d570a76f7ca197e69c2f39511380d"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x46\",\"\\x64\",\"0\",\"\\x3d\",\"\\x22\",\"\\x65\"," ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}