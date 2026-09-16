rule sig_20161024_5830958189d3b98cc488c7160327cd04 {
  meta:
    description = "datamaliciousorder - file 20161024_5830958189d3b98cc488c7160327cd04.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d955a53492d03eda5505f40f342514dad8892d7523d2cfff3db2c338b35f44db"

  strings:
    $s1 = "} while (om++ < gv);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}