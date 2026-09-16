rule sig_20160826_d40d803b72fe1b4d8bc9e24487ba5316 {
  meta:
    description = "datamaliciousorder - file 20160826_d40d803b72fe1b4d8bc9e24487ba5316.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81ad08321e9cfd773b23cfe032b42034ec8edff3ac297242cee3bd0f341d83b5"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4f\",\"3\",\"\\x3d\",\"\\x22\",\"\\x73\",\"\\x65\"," ascii
    $s2 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4f\",\"3\",\"\\x3d\",\"\\x22\",\"\\x73\",\"\\x65\"," ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}