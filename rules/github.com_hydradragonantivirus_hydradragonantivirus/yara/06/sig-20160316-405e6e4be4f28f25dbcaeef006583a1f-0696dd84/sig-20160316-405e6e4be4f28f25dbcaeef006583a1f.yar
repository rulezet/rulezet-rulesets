rule sig_20160316_405e6e4be4f28f25dbcaeef006583a1f {
  meta:
    description = "datamaliciousorder - file 20160316_405e6e4be4f28f25dbcaeef006583a1f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7237b1cb719618684c73a8c58857fd310f6f69385bb5f4895dae5497ca017a43"

  strings:
    $s1  = "aiTcYD = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 &" ascii
    $s2  = " ] || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s3  = "owoUPUIBG.onreadystatechange = function () {" fullword ascii
    $s4  = "aiTcYD = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 &" ascii
    $s5  = "    bBeraIS[PtnXyUs[timedI+1]](FTjsxFFh, 1, \"PECrEBeEmDD\" === \"YSMOOlsbVK\"); zLCkG = \" \\\"PSEUDO\\\": function( pseudo, ar" ascii
    $s6  = "PVPdQk = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s7  = "OYYvFbR = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s8  = "String.prototype.fluffy = function () { return this.substr(0, 1); };" fullword ascii
    $s9  = "{ pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case cu" ascii
    $s10 = "HGsaMbypqU = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ " ascii
    $s11 = "HGsaMbypqU = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ " ascii
    $s12 = "var NxsWb = this[extraordinary];" fullword ascii
    $s13 = "ossessed\",\"xe\"), false);" fullword ascii
    $s14 = "extraordinary = PtnXyUs[2+2+2].split(\"handmaiden\").join(\"\");" fullword ascii
    $s15 = "    owoUPUIBG.open((\"connective\",\"pollux\",\"G\")+\"ET\", \"h\"+\"tt\"+(\"firebrand\",\"spiral\",\"elliott\",\"p:\")+(\"shamb" ascii
    $s16 = "vivacious = ((\"selene\", \"syndicate\", \"TYRHcUO\", \"astounding\", \"pdVjipGveJD\") + \"nbUUoBUtuGB\").fluffy();" fullword ascii
    $s17 = "VCNdViCX = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] " ascii
    $s18 = "VCNdViCX = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] " ascii
    $s19 = "        LyPzmite = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) { un" ascii
    $s20 = "        LPoiBJLQAul = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; " ascii

  condition:
    uint16(0) == 0x4251 and
    8 of them
}