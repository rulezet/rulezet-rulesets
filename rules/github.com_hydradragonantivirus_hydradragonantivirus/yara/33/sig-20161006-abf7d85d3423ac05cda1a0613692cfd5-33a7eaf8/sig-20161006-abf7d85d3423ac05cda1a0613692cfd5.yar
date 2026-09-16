rule sig_20161006_abf7d85d3423ac05cda1a0613692cfd5 {
  meta:
    description = "datamaliciousorder - file 20161006_abf7d85d3423ac05cda1a0613692cfd5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "35de37504fd0c319113e2500837e227b2158edb9f2becf7ba88f98ea8b39e05e"

  strings:
    $s1 = "} while (dz0++ < (oi[\"l\"+\"engt\"+\"h\"]-1));" fullword ascii

  condition:
    uint16(0) == 0x2f0a and
    all of them
}