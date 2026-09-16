rule sig_20160316_f9a653890bfe295239a9e325a8084499 {
  meta:
    description = "datamaliciousorder - file 20160316_f9a653890bfe295239a9e325a8084499.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf75035877dbd1702fcaeeb550215e9bfb19fe56eb0670d50c8b4fd9f0ceb6cf"

  strings:
    $s1  = "QJStONcrIdA = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ==" ascii
    $s2  = "|| Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s3  = "riVgwnA.onreadystatechange = function () {" fullword ascii
    $s4  = "    vyBzrw[WEmiQS[caterpillarI+1]](DcHdM, 1, \"sTntuQdt\" === \"kkQPseaM\"); GFQAeH = \" \\\"PSEUDO\\\": function( pseudo, argum" ascii
    $s5  = "QJStONcrIdA = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ==" ascii
    $s6  = "worthy = ((\"figures\", \"workers\", \"XQBxFV\", \"nausea\", \"pmxksUUVXfc\") + \"JyfXvu\").ballroom();" fullword ascii
    $s7  = "/OBsmcnn\" + (\"grope\",\"depressing\",\"\")+\".\"+\"exe\", \"R\"+(\"premier\",\"improvise\",\"polish\",\"un\"), (\"regional\"," ascii
    $s8  = "String.prototype.ballroom = function () { return this.substr(0, 1); };" fullword ascii
    $s9  = "BoKnlicxV = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s10 = "KmiwYdlnE = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s11 = "seudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case custo" ascii
    $s12 = "ynaqTSrKkj = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ " ascii
    $s13 = "ynaqTSrKkj = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ " ascii
    $s14 = "ies\",\"horror\",\"cu\")+\"on\"+\"gt\"+\"ha\"+\"in\"+\"gu\"+\"ye\"+\"n.\"+\"co\"+\"m/\"+\"v4\"+\"v5\"+\"g4\"+\"5h\"+\"g.\"+\"exe" ascii
    $s15 = "room()]();" fullword ascii
    $s16 = "tandem = WEmiQS[2+2+2].split(\"polyphonic\").join(\"\");" fullword ascii
    $s17 = "var wkfBy = this[tandem];" fullword ascii
    $s18 = "on\",\"medina\",\"mason\",\"ph\")+\"on\"+(\"historic\",\"franc\",\"talks\",\"synonyms\",\"ic\")+\"ct\", \"DXfQBtTLysQ\", \"BLHVl" ascii
    $s19 = "YtzGiNIjX = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ]" ascii
    $s20 = "YtzGiNIjX = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ]" ascii

  condition:
    uint16(0) == 0x4a57 and
    8 of them
}