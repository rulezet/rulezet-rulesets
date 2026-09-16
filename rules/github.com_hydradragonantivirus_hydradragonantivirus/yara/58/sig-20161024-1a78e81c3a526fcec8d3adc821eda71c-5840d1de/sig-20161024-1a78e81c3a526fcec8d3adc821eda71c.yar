rule sig_20161024_1a78e81c3a526fcec8d3adc821eda71c {
  meta:
    description = "datamaliciousorder - file 20161024_1a78e81c3a526fcec8d3adc821eda71c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb0eb2bc90f3e2d20de4dd491a64def6283df6284ca597235f782c27f329db49"

  strings:
    $s1 = "} while (co++ < gn0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}