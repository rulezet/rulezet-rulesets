rule sig_20160316_4ae19f0bd7b699c05ba7eab7802d8007 {
  meta:
    description = "datamaliciousorder - file 20160316_4ae19f0bd7b699c05ba7eab7802d8007.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa2d6a78b429c8436c2771cd8bf8b65b795fa16e639ac890ca48b2b2c9407a54"

  strings:
    $s1  = "ncuongtha\"+(\"antechamber\",\"forge\",\"shatter\",\"inguye\")+\"n.com/v4v5g4\"+\"5hg.exe\", false);" fullword ascii
    $s2  = "hTdyRAdlRAW = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ==" ascii
    $s3  = "    hoHRfa[DDhjYzys[accomplishI+1]](xSicFM, 1, \"QJphWbnUafw\" === \"VDSLAebDC\"); JxlBm = \" \\\"PSEUDO\\\": function( pseudo, " ascii
    $s4  = "MopuAqHCJ.onreadystatechange = function () {" fullword ascii
    $s5  = "do ] || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s6  = "    MopuAqHCJ.open(\"G\"+(\"dormant\",\"husband\",\"usefully\",\"irritable\",\"ET\"), \"h\"+(\"invective\",\"cornell\",\"friendl" ascii
    $s7  = "hTdyRAdlRAW = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ==" ascii
    $s8  = "shuttle = ((\"leonine\", \"disruption\", \"ygxWTrXR\", \"hexameter\", \"pMUnmoFkRI\") + \"OVPFOO\").haiti();" fullword ascii
    $s9  = "comparison = DDhjYzys[2+2+2].split(\"endangered\").join(\"\");" fullword ascii
    $s10 = "uwBKwHa = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s11 = "String.prototype.haiti = function () { return this.substr(0, 1); };" fullword ascii
    $s12 = "OBrKqOW = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s13 = "var NXNFcC = this[comparison];" fullword ascii
    $s14 = ") { pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case " ascii
    $s15 = "vaIQjB = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ];" ascii
    $s16 = "vaIQjB = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ];" ascii
    $s17 = "kkfyKfuTp = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ]" ascii
    $s18 = "kkfyKfuTp = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ]" ascii
    $s19 = "    hoHRfa[DDhjYzys[accomplishI+1]](xSicFM, 1, \"QJphWbnUafw\" === \"VDSLAebDC\"); JxlBm = \" \\\"PSEUDO\\\": function( pseudo, " ascii
    $s20 = "    MopuAqHCJ[encourageds + (\"assimilate\",\"stewardess\",\"indecent\",\"e\") + ((\"webcast\", \"computer\", \"pkNspt\", \"spec" ascii

  condition:
    uint16(0) == 0x424f and
    8 of them
}