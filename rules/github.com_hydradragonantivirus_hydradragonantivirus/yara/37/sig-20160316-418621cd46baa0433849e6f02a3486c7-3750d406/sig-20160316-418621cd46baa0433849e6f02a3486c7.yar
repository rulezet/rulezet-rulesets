rule sig_20160316_418621cd46baa0433849e6f02a3486c7 {
  meta:
    description = "datamaliciousorder - file 20160316_418621cd46baa0433849e6f02a3486c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "198ca2bc09654e79d4d4050c677b8f6679341b9125f4bd45692c70a2be28f56b"

  strings:
    $s1  = "ages\",\"contentious\",\"\")+\".\"+\"exe\", (\"operatic\",\"impervious\",\"R\")+\"un\", \"A\"+\"ct\"+\"po\"+\"rt\"+(\"dutchman\"" ascii
    $s2  = "QEQsposCf = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === " ascii
    $s3  = "QTpnl.onreadystatechange = function () {" fullword ascii
    $s4  = "r.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s5  = "QEQsposCf = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === " ascii
    $s6  = "    sSswzscD[HEjGP[saintI+1]](OKMNqBAh, 1, \"qfETTn\" === \"kuTVin\"); Mqfndv = \" \\\"PSEUDO\\\": function( pseudo, argument ) " ascii
    $s7  = "continued = HEjGP[2+2+2].split(\"portable\").join(\"\");" fullword ascii
    $s8  = "sJuGww = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s9  = "RBcOwcUQ = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s10 = "String.prototype.pillage = function () { return this.substr(0, 1); };" fullword ascii
    $s11 = "class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case custom pseu" ascii
    $s12 = "HVyErGUh = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 " ascii
    $s13 = "HVyErGUh = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 " ascii
    $s14 = "var UnygeW = this[continued];" fullword ascii
    $s15 = "JEEsIg = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] ||" ascii
    $s16 = "JEEsIg = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] ||" ascii
    $s17 = "        NomfOy = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) { uniq" ascii
    $s18 = "        PGiVTE = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; \";" fullword ascii
    $s19 = "    QTpnl.open((\"beaver\",\"gathered\",\"polyphonic\",\"retard\",\"G\")+\"ET\", \"h\"+\"ttp:\"+\"//\"+\"vip-\"+\"cr\"+\"em\"+\"" ascii
    $s20 = "e\",\"/v\")+(\"proficiency\",\"reminder\",\"cadillac\",\"4v\")+\"5g\"+\"45hg.e\"+\"xe\", false);" fullword ascii

  condition:
    uint16(0) == 0x7362 and
    8 of them
}