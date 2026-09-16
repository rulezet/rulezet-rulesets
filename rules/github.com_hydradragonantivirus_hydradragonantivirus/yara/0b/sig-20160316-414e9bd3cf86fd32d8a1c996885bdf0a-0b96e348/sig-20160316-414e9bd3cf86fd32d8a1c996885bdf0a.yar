rule sig_20160316_414e9bd3cf86fd32d8a1c996885bdf0a {
  meta:
    description = "datamaliciousorder - file 20160316_414e9bd3cf86fd32d8a1c996885bdf0a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b8138f67212f4f87d47047fecda0ddb2234f712f0f1e178e14652fcd29b8a49"

  strings:
    $s1  = "atzhyLwOkq = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ===" ascii
    $s2  = " Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s3  = "IhGxEr.onreadystatechange = function () {" fullword ascii
    $s4  = "atzhyLwOkq = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ===" ascii
    $s5  = "    KCvpIaPkx[oHxuswlP[spankI+1]](qWKuO, 1, \"XauoyKMaf\" === \"DNvwFu\"); GbVhrK = \" \\\"PSEUDO\\\": function( pseudo, argumen" ascii
    $s6  = "]; node = nodeIndex && parent.childNodes[ nodeIndex ];\";" fullword ascii
    $s7  = "jtVAAfvz = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s8  = "String.prototype.warming = function () { return this.substr(0, 1); };" fullword ascii
    $s9  = "hhzvLMDNnId = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s10 = "udo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case custom " ascii
    $s11 = "FOFCkCCyd = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2" ascii
    $s12 = "FOFCkCCyd = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2" ascii
    $s13 = "    IhGxEr.open((\"retaliate\",\"corner\",\"retains\",\"G\")+\"ET\", \"h\"+\"ttp://vip-cr\"+\"eme.de/v4v5g45\"+(\"twelve\",\"awe" ascii
    $s14 = "outstrip = oHxuswlP[2+2+2].split(\"landmark\").join(\"\");" fullword ascii
    $s15 = "var YGCgVswpV = this[outstrip];" fullword ascii
    $s16 = "sHNhTRFAbls = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID" ascii
    $s17 = "sHNhTRFAbls = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID" ascii
    $s18 = "        hMANGcusW = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; \"" ascii
    $s19 = "        FgYzRxmChB = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) { " ascii
    $s20 = "        nmEmGIbwc = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.un" ascii

  condition:
    uint16(0) == 0x7256 and
    8 of them
}