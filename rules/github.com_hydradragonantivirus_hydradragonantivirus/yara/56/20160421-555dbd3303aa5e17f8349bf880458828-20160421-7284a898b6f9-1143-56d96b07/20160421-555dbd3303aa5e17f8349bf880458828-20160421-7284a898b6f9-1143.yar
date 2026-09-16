rule _20160421_555dbd3303aa5e17f8349bf880458828_20160421_7284a898b6f9_1143 {
  meta:
    description = "datamaliciousorder - from files 20160421_555dbd3303aa5e17f8349bf880458828.js, 20160421_7284a898b6f99c109507e2dd666cb1f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3839eaae76072a9b0f8876581137ebfd4efa2d26e5018ddba03b103f829c882"
    hash2       = "5a6cad063d7563d3a4de388fc8ecc7fb9ad346d2d3485f94599e7798623e4c51"

  strings:
    $s1 = "var furthermore = new proportionate(overlaid[1]);" fullword ascii
    $s2 = "BzVAQOqRH = \" Convert non-html into a text node } else if ( !rhtml.test( elem ) ) { nodes.push( context.createTextNode( elem ) " ascii
    $s3 = "BzVAQOqRH = \" Convert non-html into a text node } else if ( !rhtml.test( elem ) ) { nodes.push( context.createTextNode( elem ) " ascii
    $s4 = "var limited = \"S\";" fullword ascii
    $s5 = "function popped(richardson, jason) {" fullword ascii
    $s6 = "var pendulous = Math.random() ;" fullword ascii
    $s7 = "        furthermore[commiseration.shift()](continuity, slothful2, \"wVTNRT\" === \"PeqneIxT\"); XLabHO = \" Fix #12392 for oldIE" ascii
    $s8 = "        furthermore[commiseration.shift()](continuity, slothful2, \"wVTNRT\" === \"PeqneIxT\"); XLabHO = \" Fix #12392 for oldIE" ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}