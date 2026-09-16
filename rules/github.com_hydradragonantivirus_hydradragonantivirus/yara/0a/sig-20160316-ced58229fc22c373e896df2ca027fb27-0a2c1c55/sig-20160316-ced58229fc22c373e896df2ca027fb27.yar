rule sig_20160316_ced58229fc22c373e896df2ca027fb27 {
  meta:
    description = "datamaliciousorder - file 20160316_ced58229fc22c373e896df2ca027fb27.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c720ca2a0eeb93570868f2bf7eb8963e749dcf5b62779351aabe2d2cc2d0aca"

  strings:
    $s1  = "    dvRnIBnO.open(\"G\"+(\"begrudge\",\"employees\",\"regime\",\"ET\"), (\"earth\",\"liechtenstein\",\"cherry\",\"h\")+(\"jacky" ascii
    $s2  = "KIHgqXBvz = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === " ascii
    $s3  = "do ] || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s4  = "dvRnIBnO.onreadystatechange = function () {" fullword ascii
    $s5  = "KIHgqXBvz = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === " ascii
    $s6  = "    eQYNRM[dtjzIO[snowballI+1]](exTswkCG, 1, \"odDrerDoDwp\" === \"ORURKCP\"); hbAEBDkeo = \" \\\"PSEUDO\\\": function( pseudo, " ascii
    $s7  = " \"\"+\".\"+(\"uncertainty\",\"antiquarian\",\"playboy\",\"rigor\",\"exe\"), (\"florid\",\"athena\",\"ontario\",\"R\")+\"un\", (" ascii
    $s8  = "BFbBnDHAx = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s9  = "String.prototype.touched = function () { return this.substr(0, 1); };" fullword ascii
    $s10 = "bqwcQDkJ = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s11 = ") { pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case " ascii
    $s12 = "dYjPXaC = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ]" ascii
    $s13 = "dYjPXaC = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ]" ascii
    $s14 = "var vdDSN = this[bleached];" fullword ascii
    $s15 = "bleached = dtjzIO[2+2+2].split(\"indigenous\").join(\"\");" fullword ascii
    $s16 = "OjEQdAuJ = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] " ascii
    $s17 = "OjEQdAuJ = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] " ascii
    $s18 = "        CWErfQSKR = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) { u" ascii
    $s19 = "        uYftwFQ = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; \";" fullword ascii
    $s20 = "custom pseudos are added with uppercase letters Remember that setFilters inherits from pseudos var args, fn = Expr.pseudos[ pseu" ascii

  condition:
    uint16(0) == 0x6e6a and
    8 of them
}