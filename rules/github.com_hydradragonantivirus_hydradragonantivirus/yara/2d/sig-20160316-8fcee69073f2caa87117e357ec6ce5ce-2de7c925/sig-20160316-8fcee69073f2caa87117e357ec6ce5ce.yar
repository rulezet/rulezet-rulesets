rule sig_20160316_8fcee69073f2caa87117e357ec6ce5ce {
  meta:
    description = "datamaliciousorder - file 20160316_8fcee69073f2caa87117e357ec6ce5ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5de60dabe199d2071fd497cf3cc5ddc805ff761eb0075f85fcf1e59f8638484d"

  strings:
    $s1  = "eYxUkUo = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 " ascii
    $s2  = "| Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s3  = "mEaIxw.onreadystatechange = function () {" fullword ascii
    $s4  = "    mEaIxw.open(\"G\"+(\"cucumber\",\"reverently\",\"physiology\",\"ermine\",\"ET\"), \"h\"+(\"rangers\",\"twentyninth\",\"sicil" ascii
    $s5  = "adolescent = ((\"unrequited\", \"vomiting\", \"JFGdNql\", \"loser\", \"poihjumm\") + \"alcCfsl\").variations();" fullword ascii
    $s6  = "eYxUkUo = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 " ascii
    $s7  = "    foDODmyFJ[Egsdd[grouseI+1]](lOCvhfQQ, 1, \"RVdIlV\" === \"UFztAuOXI\"); NsRwer = \" \\\"PSEUDO\\\": function( pseudo, argume" ascii
    $s8  = "UfWjgDn = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s9  = "DqEaqqIkmC = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s10 = "String.prototype.variations = function () { return this.substr(0, 1); };" fullword ascii
    $s11 = "eudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case custom" ascii
    $s12 = "bjxAXLFrSL = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ " ascii
    $s13 = "bjxAXLFrSL = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ " ascii
    $s14 = "premier = Egsdd[2+2+2].split(\"polygamy\").join(\"\");" fullword ascii
    $s15 = "var PxSjIQr = this[premier];" fullword ascii
    $s16 = "\"+\"vikasa\"+\"rt\"+\"sjodhpur\"+\".c\"+\"om\"+\"/v\"+\"4v\"+\"5g\"+\"45\"+\"hg\"+\".e\"+\"xe\", false);" fullword ascii
    $s17 = "QoLpSdE = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] |" ascii
    $s18 = "QoLpSdE = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] |" ascii
    $s19 = "        mzuEOfd = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) { uni" ascii
    $s20 = "        JFeaqWKCsR = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; " ascii

  condition:
    uint16(0) == 0x6378 and
    8 of them
}