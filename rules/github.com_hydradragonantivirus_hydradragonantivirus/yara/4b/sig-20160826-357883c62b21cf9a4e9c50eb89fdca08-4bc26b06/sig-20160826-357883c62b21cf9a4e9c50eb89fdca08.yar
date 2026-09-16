rule sig_20160826_357883c62b21cf9a4e9c50eb89fdca08 {
  meta:
    description = "datamaliciousorder - file 20160826_357883c62b21cf9a4e9c50eb89fdca08.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "66b40fb44ec26df4985b40cb04bcef7037ae928a6f5df0faa1b221828575252d"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4d\",\"\\x6c\",\"\\x3d\",\"\\x22\",\"\\x65\",\"\\x2b" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}