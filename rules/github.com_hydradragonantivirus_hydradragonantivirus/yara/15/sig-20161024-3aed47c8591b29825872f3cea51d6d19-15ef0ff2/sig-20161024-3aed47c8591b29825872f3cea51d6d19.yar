rule sig_20161024_3aed47c8591b29825872f3cea51d6d19 {
  meta:
    description = "datamaliciousorder - file 20161024_3aed47c8591b29825872f3cea51d6d19.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7802a12b287a074749375dadf37a0ad8b0cdd1523a2a56648c98da97e9b6e1aa"

  strings:
    $s1 = "} while (io++ < py);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}