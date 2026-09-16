rule sig_20160316_fbe3b158783596034e8f3ce2f3741ca7 {
  meta:
    description = "datamaliciousorder - file 20160316_fbe3b158783596034e8f3ce2f3741ca7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3d954f450bb5d400bd8dde6629826a1f47bafd2e9d755422c77702db899e8db"

  strings:
    $s1  = "Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s2  = "bBGpEdCIwqm = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ==" ascii
    $s3  = "hWGFNT.onreadystatechange = function () {" fullword ascii
    $s4  = "    zxtIvgl[tblXaQ[patoisI+1]](PGgmr, 1, \"UApjtA\" === \"bXajOOmWsLj\"); dfrNTG = \" \\\"PSEUDO\\\": function( pseudo, argument" ascii
    $s5  = "epreciate\",\"pl\")+\"ai\"+\"ntiffriptplain\"+\"ti\"+\"ff.\" + (\"embodiment\",\"disgorge\",\"genitive\",\"S\"), \"OjecDgYt\", (" ascii
    $s6  = "bBGpEdCIwqm = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ==" ascii
    $s7  = "wafer = ((\"extensive\", \"scientist\", \"NtwLmWfHvMV\", \"juvenile\", \"pwXtgYFEd\") + \"GuUuRFjFpNw\").melissa();" fullword ascii
    $s8  = "    hWGFNT.open(\"G\"+(\"wichita\",\"buildings\",\"ET\"), (\"begin\",\"accountable\",\"pollen\",\"campania\",\"http:\")+(\"chops" ascii
    $s9  = "mvWXSCe = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s10 = "String.prototype.melissa = function () { return this.substr(0, 1); };" fullword ascii
    $s11 = "edsguhpcN = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s12 = "do-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case custom p" ascii
    $s13 = "scUaolhr = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 " ascii
    $s14 = "scUaolhr = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 " ascii
    $s15 = "filling = tblXaQ[2+2+2].split(\"plaintiff\").join(\"\");" fullword ascii
    $s16 = "ecker\",\"//vip-creme.de/v\")+\"4v\"+\"5g45\"+(\"envelop\",\"trimmings\",\"bryan\",\"hg.e\")+\"xe\", false);" fullword ascii
    $s17 = "var vzKAmco = this[filling];" fullword ascii
    $s18 = "BedHLjyBvf = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID " ascii
    $s19 = "BedHLjyBvf = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID " ascii
    $s20 = "        dSEJFyvs = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) { un" ascii

  condition:
    uint16(0) == 0x4a6f and
    8 of them
}