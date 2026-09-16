rule sig_20160316_c6b91475f493bc068537641622a0bcf0 {
  meta:
    description = "datamaliciousorder - file 20160316_c6b91475f493bc068537641622a0bcf0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12675fb4f24a56e3e4fa26b83aa3f83c0a0940b805c819a5855bd2682abc2ab7"

  strings:
    $s1  = "\",\"confidentiality\",\"levity\",\"v4v5g4\")+\"5h\"+\"g.exe\", false);" fullword ascii
    $s2  = "DexXgA = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 &" ascii
    $s3  = " ] || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s4  = "AduWd.onreadystatechange = function () {" fullword ascii
    $s5  = "    AduWd.open(\"G\"+(\"medicare\",\"taciturnity\",\"ET\"), (\"betty\",\"wooden\",\"scientists\",\"http://va\")+(\"mounts\",\"al" ascii
    $s6  = "    NOCEP[RchRHY[gelatineI+1]](rwaEnb, 1, \"PzDmWnGU\" === \"wUXKNHIbgEO\"); FBtutnbfb = \" \\\"PSEUDO\\\": function( pseudo, ar" ascii
    $s7  = "DexXgA = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 &" ascii
    $s8  = "furniture = ((\"interrogatory\", \"houseboat\", \"ufHInySYNid\", \"twenty\", \"pBSqAQSLsDRw\") + \"zSPlGAMu\").affray();" fullword ascii
    $s9  = "IKjJQHF = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s10 = "wBsgQxDpMsX = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s11 = "parc\",\"le\")+(\"ordnance\",\"collectors\",\"ri\")+(\"filament\",\"sublimate\",\"ea\")+\"nn\"+\"efashion\"+\"s.\"+\"co.u\"+\"k/" ascii
    $s12 = "String.prototype.affray = function () { return this.substr(0, 1); };" fullword ascii
    $s13 = "{ pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case cu" ascii
    $s14 = "GXAxkUN = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ]" ascii
    $s15 = "GXAxkUN = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ]" ascii
    $s16 = "principality = RchRHY[2+2+2].split(\"homespun\").join(\"\");" fullword ascii
    $s17 = "var TrvceOA = this[principality];" fullword ascii
    $s18 = "RHiKlEoeWmM = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID" ascii
    $s19 = "RHiKlEoeWmM = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID" ascii
    $s20 = "        caGBGleeNmz = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) {" ascii

  condition:
    uint16(0) == 0x526c and
    8 of them
}