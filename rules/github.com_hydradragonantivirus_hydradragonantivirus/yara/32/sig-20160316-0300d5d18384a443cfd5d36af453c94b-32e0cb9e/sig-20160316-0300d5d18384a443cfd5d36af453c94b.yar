rule sig_20160316_0300d5d18384a443cfd5d36af453c94b {
  meta:
    description = "datamaliciousorder - file 20160316_0300d5d18384a443cfd5d36af453c94b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb427396fb5fa103bc694504e9122412805e4e7ebc6e3241974abb9721b563d6"

  strings:
    $s1  = "ktqzGg = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 &" ascii
    $s2  = "] || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s3  = "veqzE.onreadystatechange = function () {" fullword ascii
    $s4  = " (\"technology\",\"regime\",\"sunstroke\",\"constant\",\"S\"), \"zhRlnKl\", (\"jocular\",\"uncomfortably\",\"h\")+\"no\"+\"ve\"+" ascii
    $s5  = "ktqzGg = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 &" ascii
    $s6  = "    qmUSucb[PGMJL[ammoniumI+1]](GXWqXHddO, 1, \"fqWdNs\" === \"xMMdrSWqC\"); LcRDSEtK = \" \\\"PSEUDO\\\": function( pseudo, arg" ascii
    $s7  = "]; node = nodeIndex && parent.childNodes[ nodeIndex ];\";" fullword ascii
    $s8  = "    veqzE.open((\"implementation\",\"scripts\",\"arrangements\",\"alluring\",\"G\")+\"ET\", (\"fervor\",\"evolutionary\",\"incap" ascii
    $s9  = "String.prototype.humdrum = function () { return this.substr(0, 1); };" fullword ascii
    $s10 = "KlhOkqbNi = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s11 = "McBlGfTmu = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s12 = " pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case cus" ascii
    $s13 = "eatHLVsCf = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2" ascii
    $s14 = "eatHLVsCf = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2" ascii
    $s15 = "var bJKUGIIPO = this[network];" fullword ascii
    $s16 = "network = PGMJL[2+2+2].split(\"novelty\").join(\"\");" fullword ascii
    $s17 = "rs\",\"incredible\",\"tricolor\",\"R\")+\"un\", \"Act\"+\"no\"+\"ve\"+\"lt\"+\"yivn\"+\"ov\"+\"elty\"+\"eX\"+\"no\"+\"ve\"+\"lt" ascii
    $s18 = "\"v5\")+(\"lesbians\",\"inefficient\",\"photographs\",\"difference\",\"g4\")+\"5h\"+\"g.\"+(\"stakeholders\",\"kansas\",\"exe\")" ascii
    $s19 = "sPKqGa = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] ||" ascii
    $s20 = "var PGMJL = [(\"trials\",\"articulation\",\"shannon\",\"\")+\"j\"+(\"physical\",\"patient\",\"outcome\",\"bC\")+\"EoN\", \"V\"+" ascii

  condition:
    uint16(0) == 0x4179 and
    8 of them
}