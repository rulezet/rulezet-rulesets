rule sig_20160316_83031e92f756be4a4c72aeda71e958db {
  meta:
    description = "datamaliciousorder - file 20160316_83031e92f756be4a4c72aeda71e958db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6058544c8873cf8e139672ff5310887fd8a0abb95d4b1cf67fe847eed816adb8"

  strings:
    $s1  = "    vwdRJild.open((\"irrational\",\"breaks\",\"horoscope\",\"G\")+\"ET\", (\"vestibule\",\"hudson\",\"h\")+(\"shanghai\",\"inact" ascii
    $s2  = "    yfDIwLyQ[OIoQamroh[somewhereI+1]](binTCDf, 1, \"fQGwXueGA\" === \"kUPAbbLjnY\"); fhONWrFSH = \" \\\"PSEUDO\\\": function( ps" ascii
    $s3  = "xwYaYSx = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 " ascii
    $s4  = "[ pseudo ] || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s5  = "vwdRJild.onreadystatechange = function () {" fullword ascii
    $s6  = "convivial = ((\"wheelbarrow\", \"madeline\", \"WkrdAKd\", \"idealized\", \"pJGcXsgnpel\") + \"OtowOG\").synopsis();" fullword ascii
    $s7  = "xwYaYSx = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 " ascii
    $s8  = "NtCCzVG = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s9  = "heSeuA = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s10 = "String.prototype.synopsis = function () { return this.substr(0, 1); };" fullword ascii
    $s11 = "ument ) { pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in" ascii
    $s12 = "KDdVQtaDBb = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ " ascii
    $s13 = "KDdVQtaDBb = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ " ascii
    $s14 = "synopsis()]();" fullword ascii
    $s15 = "statistics = OIoQamroh[2+2+2].split(\"miami\").join(\"\");" fullword ascii
    $s16 = "var WWimBk = this[statistics];" fullword ascii
    $s17 = "EduGasJaoc = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID " ascii
    $s18 = "EduGasJaoc = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID " ascii
    $s19 = "    yfDIwLyQ[OIoQamroh[somewhereI+1]](binTCDf, 1, \"fQGwXueGA\" === \"kUPAbbLjnY\"); fhONWrFSH = \" \\\"PSEUDO\\\": function( ps" ascii
    $s20 = "        XLUskJhkinm = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) {" ascii

  condition:
    uint16(0) == 0x6b69 and
    8 of them
}