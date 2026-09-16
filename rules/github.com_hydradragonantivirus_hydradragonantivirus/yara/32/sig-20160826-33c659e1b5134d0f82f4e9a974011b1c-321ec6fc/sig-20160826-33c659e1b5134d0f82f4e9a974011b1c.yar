rule sig_20160826_33c659e1b5134d0f82f4e9a974011b1c {
  meta:
    description = "datamaliciousorder - file 20160826_33c659e1b5134d0f82f4e9a974011b1c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d2f25ed6bd48ab3234f4511d9a204e2c2ba5bdd8e25a0282f9b8ec027afd039"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x46\",\"\\x57\",\"0\",\"\\x3d\",\"\\x22\",\"\\x65\"," ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}