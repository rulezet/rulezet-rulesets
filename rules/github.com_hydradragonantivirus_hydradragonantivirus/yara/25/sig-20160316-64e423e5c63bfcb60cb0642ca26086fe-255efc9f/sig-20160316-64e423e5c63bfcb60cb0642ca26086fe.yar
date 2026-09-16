rule sig_20160316_64e423e5c63bfcb60cb0642ca26086fe {
  meta:
    description = "datamaliciousorder - file 20160316_64e423e5c63bfcb60cb0642ca26086fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa62795db5226fb807e0c7cf6ad2ba8de7f02c64c1f1d00052a1a0179c740593"

  strings:
    $s1  = "%\", \"/fxGDCDyc\" + \"\"+\".\"+(\"expostulation\",\"chunk\",\"abridge\",\"commentary\",\"exe\"), (\"sensitive\",\"motherinlaw\"" ascii
    $s2  = "PAsTRASp = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0" ascii
    $s3  = "] || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s4  = "MvYTskdEK.onreadystatechange = function () {" fullword ascii
    $s5  = "    Fnvzdk[RHkTDiN[causesI+1]](uooMeqL, 1, \"rNWjCt\" === \"dWSXddoECCu\"); yCqHbCHJo = \" \\\"PSEUDO\\\": function( pseudo, arg" ascii
    $s6  = "PAsTRASp = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0" ascii
    $s7  = "pollux = ((\"colds\", \"pronoun\", \"MXEPbjtxAnL\", \"succeed\", \"pgCBAeXrzL\") + \"KTOzAbyCTQh\").train();" fullword ascii
    $s8  = "clJKcfWDWFX = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s9  = "JixWGH = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s10 = "String.prototype.train = function () { return this.substr(0, 1); };" fullword ascii
    $s11 = " pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case cus" ascii
    $s12 = "xcRmbLli = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 " ascii
    $s13 = "xcRmbLli = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 " ascii
    $s14 = "r\",\"unfaithful\",\"hours\",\"lawlessness\",\"ff\")+\"Oj\"+\"DUO\", \"E\"+\"xpan\"+\"dE\"+(\"wicker\",\"acorn\",\"nvir\")+(\"il" ascii
    $s15 = "var hnzFIUBka = this[sagacious];" fullword ascii
    $s16 = "sagacious = RHkTDiN[2+2+2].split(\"separable\").join(\"\");" fullword ascii
    $s17 = "McpchHUMS = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ]" ascii
    $s18 = "McpchHUMS = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ]" ascii
    $s19 = "        ehnBAa = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; \";" fullword ascii
    $s20 = "        qkqBedaHnp = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) { " ascii

  condition:
    uint16(0) == 0x4956 and
    8 of them
}