rule sig_20160826_e1eae48ab861a86351b19867adbcc7dc {
  meta:
    description = "datamaliciousorder - file 20160826_e1eae48ab861a86351b19867adbcc7dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00f561009d92e36d76372b3baceeb6ec97e43f0bd1349ed34e706be20835daa7"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x44\",\"\\x49\",\"\\x6c\",\"\\x3d\",\"\\x22\",\"\\x6f" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}