rule sig_20160316_31ff39a4c7e12afd6785e9e4d3b9acb3 {
  meta:
    description = "datamaliciousorder - file 20160316_31ff39a4c7e12afd6785e9e4d3b9acb3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a6ecf7463153f0ef7dda5f6cd6ece30c176d2ca5f53e56aaeb2083bf905d936"

  strings:
    $s1  = "    vqdfw.open((\"itunes\",\"coolie\",\"G\")+\"ET\", \"http:\"+\"//\"+(\"reciprocity\",\"mario\",\"quotes\",\"unless\",\"tratanc" ascii
    $s2  = "m/v4v5g45hg.exe\", false);" fullword ascii
    $s3  = "cimywWsitk = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ===" ascii
    $s4  = " Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s5  = "vqdfw.onreadystatechange = function () {" fullword ascii
    $s6  = "entry = ((\"statutes\", \"scandinavia\", \"uIwvCUbb\", \"queensland\", \"pqlwQIJqLa\") + \"uarVEyQPtdC\").excel();" fullword ascii
    $s7  = "    kVzID[pKEbw[unmindfulI+1]](gociKmNzI, 1, \"HtzXYHU\" === \"vdGkBU\"); MNWKPpC = \" \\\"PSEUDO\\\": function( pseudo, argumen" ascii
    $s8  = "cimywWsitk = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ===" ascii
    $s9  = "]; node = nodeIndex && parent.childNodes[ nodeIndex ];\";" fullword ascii
    $s10 = "TbfKxkNE = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s11 = "String.prototype.excel = function () { return this.substr(0, 1); };" fullword ascii
    $s12 = "cqETNxF = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s13 = "udo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case custom " ascii
    $s14 = "ERNqdcizd = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2" ascii
    $s15 = "ERNqdcizd = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2" ascii
    $s16 = "var wuYKSev = this[aware];" fullword ascii
    $s17 = "aware = pKEbw[2+2+2].split(\"backing\").join(\"\");" fullword ascii
    $s18 = "YEiavglhN = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ]" ascii
    $s19 = "    zGeTdc = \" uniqueCache[ type ] = [ dirruns, diff ]; \";" fullword ascii
    $s20 = "YEiavglhN = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ]" ascii

  condition:
    uint16(0) == 0x544f and
    8 of them
}