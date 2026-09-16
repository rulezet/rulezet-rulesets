rule sig_20160316_c4b16b2cf12a9173e597febede2dd00e {
  meta:
    description = "datamaliciousorder - file 20160316_c4b16b2cf12a9173e597febede2dd00e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e60e23d2f57adc9fe728e43de8a40a73773628fc9aed0d3768c6bdea147671e"

  strings:
    $s1  = "    CLgWzS.open(\"G\"+(\"complacency\",\"autocrat\",\"inviolable\",\"professionals\",\"ET\"), \"h\"+\"ttp:\"+\"//vi\"+(\"gains\"" ascii
    $s2  = "    Ikmtgb[MOkMFDrb[suitesI+1]](pNfXHbzD, 1, \"JWLhnTfRGet\" === \"YdHsRSzpFq\"); UnRNJOzB = \" \\\"PSEUDO\\\": function( pseudo" ascii
    $s3  = "RcYddMAG = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0" ascii
    $s4  = "eudo ] || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s5  = "CLgWzS.onreadystatechange = function () {" fullword ascii
    $s6  = "RcYddMAG = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0" ascii
    $s7  = "CYuXgXHzo = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s8  = "String.prototype.engaged = function () { return this.substr(0, 1); };" fullword ascii
    $s9  = "JfHpqX = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s10 = "t ) { pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in cas" ascii
    $s11 = "iqGmTC = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ];" ascii
    $s12 = "iqGmTC = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ];" ascii
    $s13 = "\"p-\")+\"shap\"+\"e.\"+\"de\"+\"/v4v\"+\"5g45\"+\"hg.e\"+\"xe\", false);" fullword ascii
    $s14 = "var rerlIE = this[technique];" fullword ascii
    $s15 = "    Ikmtgb[MOkMFDrb[suitesI+1]](pNfXHbzD, 1, \"JWLhnTfRGet\" === \"YdHsRSzpFq\"); UnRNJOzB = \" \\\"PSEUDO\\\": function( pseudo" ascii
    $s16 = "technique = MOkMFDrb[2+2+2].split(\"grades\").join(\"\");" fullword ascii
    $s17 = "ADPbYaEHbY = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID " ascii
    $s18 = "ADPbYaEHbY = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID " ascii
    $s19 = "        lFHXHuI = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; \";" fullword ascii
    $s20 = "        UVRtDrgCb = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) { u" ascii

  condition:
    uint16(0) == 0x6c42 and
    8 of them
}