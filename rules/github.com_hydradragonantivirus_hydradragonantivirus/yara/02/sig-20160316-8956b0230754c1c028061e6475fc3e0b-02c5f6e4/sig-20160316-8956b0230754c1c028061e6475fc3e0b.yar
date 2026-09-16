rule sig_20160316_8956b0230754c1c028061e6475fc3e0b {
  meta:
    description = "datamaliciousorder - file 20160316_8956b0230754c1c028061e6475fc3e0b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "996c05433423ad21f65047f3832c42eb65e14b7810822e3de8aed5dd49285482"

  strings:
    $s1  = "empo\",\"swimming\",\"leaving\",\".exe\"), false);" fullword ascii
    $s2  = "CKCoeVbOAsK = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ==" ascii
    $s3  = "eudo ] || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s4  = "KxQylpRtR.onreadystatechange = function () {" fullword ascii
    $s5  = "    KxQylpRtR.open((\"candlestick\",\"gibbet\",\"arrangements\",\"G\")+\"ET\", \"h\"+\"ttp://vikasa\"+(\"derek\",\"hearsay\",\"c" ascii
    $s6  = "    ESOogQl[TnGEcrSXo[taughtI+1]](fIXrRYza, 1, \"BzdSryHJwep\" === \"etcRalxu\"); RLkcGbsC = \" \\\"PSEUDO\\\": function( pseudo" ascii
    $s7  = "payday = ((\"planned\", \"recite\", \"JABTIra\", \"mammal\", \"pxWMvhASGaB\") + \"eoAAtQSaj\").boils();" fullword ascii
    $s8  = "CKCoeVbOAsK = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ==" ascii
    $s9  = "aPhpxmf = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s10 = "String.prototype.boils = function () { return this.substr(0, 1); };" fullword ascii
    $s11 = "zVvXRE = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s12 = "t ) { pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in cas" ascii
    $s13 = "LWbqrttcIw = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ " ascii
    $s14 = "LWbqrttcIw = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ " ascii
    $s15 = "var dQhSEUzx = this[elizabethan];" fullword ascii
    $s16 = "IllJhSPcQF = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID " ascii
    $s17 = "IllJhSPcQF = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID " ascii
    $s18 = "        sANuYvtPjaT = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; " ascii
    $s19 = "        HmfNzfFwf = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.un" ascii
    $s20 = "        sANuYvtPjaT = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; " ascii

  condition:
    uint16(0) == 0x4268 and
    8 of them
}