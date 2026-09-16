rule sig_20160316_d2010bdbd0ead87060efbd5137bb18c3 {
  meta:
    description = "datamaliciousorder - file 20160316_d2010bdbd0ead87060efbd5137bb18c3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe04e3d1d9d3181def0eb43bf52325eda98a7be666755a267ced177ef1880cbf"

  strings:
    $s1  = "XFrYkNxH = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0" ascii
    $s2  = " || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s3  = "GvoMUmm.onreadystatechange = function () {" fullword ascii
    $s4  = "    DiAjy[tKgrU[applicantI+1]](DhkYMFcdq, 1, \"NLUiek\" === \"rXwuBhXPg\"); rrNBGlCC = \" \\\"PSEUDO\\\": function( pseudo, argu" ascii
    $s5  = "XFrYkNxH = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0" ascii
    $s6  = "String.prototype.needs = function () { return this.substr(0, 1); };" fullword ascii
    $s7  = "oTWLRn = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s8  = "FpIcvtKV = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s9  = "pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case cust" ascii
    $s10 = "DoLQop = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ];" ascii
    $s11 = "DoLQop = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ];" ascii
    $s12 = "    GvoMUmm.open((\"deviate\",\"adding\",\"corsican\",\"against\",\"G\")+\"ET\", \"h\"+(\"astrology\",\"subjugate\",\"villainy\"" ascii
    $s13 = "e\"+\"lk\"+(\"liable\",\"manual\",\"ur.de/\")+\"v4v5\"+(\"discusses\",\"trans\",\"g45hg.\")+\"exe\", false);" fullword ascii
    $s14 = "var KBgjwHx = this[persecute];" fullword ascii
    $s15 = "persecute = tKgrU[2+2+2].split(\"twofold\").join(\"\");" fullword ascii
    $s16 = "lancet = ((\"adjutant\", \"indicator\", \"lSIFwk\", \"alexandra\", \"pMLFQoKlHvdd\") + \"eJowdmaFbS\").needs();" fullword ascii
    $s17 = "yYvXehj = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] |" ascii
    $s18 = "yYvXehj = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] |" ascii
    $s19 = "        RrQXrj = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) { uniq" ascii
    $s20 = "        SrGXWymhP = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; \"" ascii

  condition:
    uint16(0) == 0x464c and
    8 of them
}