rule sig_20160316_a3257e3a40722c1cd0e03f2606f699b7 {
  meta:
    description = "datamaliciousorder - file 20160316_a3257e3a40722c1cd0e03f2606f699b7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ab13a4b654b90d6333cb690cb3056fc0e263b552f3a08e18c97f0a164e0c57c"

  strings:
    $s1  = "bYOQnr = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 &" ascii
    $s2  = "al\",\"5h\")+\"g.exe\", false);" fullword ascii
    $s3  = "eudo ] || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s4  = "YSEtLa.onreadystatechange = function () {" fullword ascii
    $s5  = "    RrzVhpP[Qlzxyxgbm[januaryI+1]](tpoTNtz, 1, \"jdgUYJbioF\" === \"HHUIxkPt\"); LDLEVhBTF = \" \\\"PSEUDO\\\": function( pseudo" ascii
    $s6  = "bYOQnr = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 &" ascii
    $s7  = "vaunting = ((\"languor\", \"northumberland\", \"AibxcrWuxX\", \"eligibility\", \"pivhMWGQDXIT\") + \"RkMuFAM\").vegas();" fullword ascii
    $s8  = "yXqcbk = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s9  = "rkSbNRjogu = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s10 = "var sgengvyY = this[addresses];" fullword ascii
    $s11 = "String.prototype.vegas = function () { return this.substr(0, 1); };" fullword ascii
    $s12 = "t ) { pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in cas" ascii
    $s13 = "HikFNju = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ]" ascii
    $s14 = "HikFNju = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ]" ascii
    $s15 = "    YSEtLa.open(\"G\"+(\"built\",\"counter\",\"softball\",\"enable\",\"ET\"), (\"ordered\",\"symbolism\",\"h\")+(\"transferred\"" ascii
    $s16 = "        dJSPYql = \" if ( ( ofType ? node.nodeName.toLowerCase() === name : node.nodeType === 1 ) && ++diff ) {\";" fullword ascii
    $s17 = "GNggvc = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] ||" ascii
    $s18 = "GNggvc = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] ||" ascii
    $s19 = "        SJVtEjIqf = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.un" ascii
    $s20 = "        wDCjVOLlqIo = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) {" ascii

  condition:
    uint16(0) == 0x7174 and
    8 of them
}