rule sig_20160316_624d7e857841208c149800e637e69e3b {
  meta:
    description = "datamaliciousorder - file 20160316_624d7e857841208c149800e637e69e3b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96aebbde34ecdfaf88681982278a9a844703352166bda57b6998ea3d82f2d0df"

  strings:
    $s1  = "SmTEqNPoe = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === " ascii
    $s2  = " || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s3  = "UHpRN.onreadystatechange = function () {" fullword ascii
    $s4  = "    UHpRN.open((\"appropriately\",\"donor\",\"G\")+\"ET\", (\"governing\",\"crucify\",\"h\")+(\"hobby\",\"mantilla\",\"enhanceme" ascii
    $s5  = "    ktTYayEYR[IcvHyBb[honeymoonI+1]](QfOzwK, 1, \"wGPzTKzDi\" === \"HtScwL\"); pDDSr = \" \\\"PSEUDO\\\": function( pseudo, argu" ascii
    $s6  = "SmTEqNPoe = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === " ascii
    $s7  = "qOCbYs = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s8  = "vnHBjrJ = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s9  = "String.prototype.takes = function () { return this.substr(0, 1); };" fullword ascii
    $s10 = "pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case cust" ascii
    $s11 = "sEcklciK = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 " ascii
    $s12 = "sEcklciK = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 " ascii
    $s13 = "var oXneY = this[inflection];" fullword ascii
    $s14 = "inflection = IcvHyBb[2+2+2].split(\"below\").join(\"\");" fullword ascii
    $s15 = "Fx\", \"Exp\"+\"an\"+\"dE\"+(\"remarks\",\"resourceful\",\"nv\")+\"ir\"+\"on\"+\"me\"+\"ntSt\"+\"ri\"+\"ngs\", (\"cypress\",\"tr" ascii
    $s16 = "fDGjDFtYzA = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID " ascii
    $s17 = "fDGjDFtYzA = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID " ascii
    $s18 = "        vnuSyn = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) { uniq" ascii
    $s19 = "        LUjeCcalSWL = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; " ascii
    $s20 = "        LUjeCcalSWL = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; " ascii

  condition:
    uint16(0) == 0x7161 and
    8 of them
}