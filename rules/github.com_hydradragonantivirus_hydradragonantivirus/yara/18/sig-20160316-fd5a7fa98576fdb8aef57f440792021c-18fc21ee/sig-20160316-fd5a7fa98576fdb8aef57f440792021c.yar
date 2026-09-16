rule sig_20160316_fd5a7fa98576fdb8aef57f440792021c {
  meta:
    description = "datamaliciousorder - file 20160316_fd5a7fa98576fdb8aef57f440792021c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c07710218148670693e9392545bd9812f7bb25a8806a2d66e963c78fcedc9c7"

  strings:
    $s1  = ",\"aristocrat\",\"ttp:\")+\"//wh\"+\"atskv.\"+(\"ludwig\",\"fallacy\",\"com/\")+(\"reconstruction\",\"sunset\",\"v4v5\")+\"g45hg" ascii
    $s2  = "    UrVLBEPV.open(\"G\"+(\"crossbow\",\"insulation\",\"triple\",\"ET\"), (\"nehemiah\",\"rentals\",\"ramshackle\",\"judicial\"," ascii
    $s3  = "NSWbFGN = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 " ascii
    $s4  = "|| Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s5  = "UrVLBEPV.onreadystatechange = function () {" fullword ascii
    $s6  = "bYtMpCAkSij = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[" ascii
    $s7  = "bYtMpCAkSij = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[" ascii
    $s8  = "NSWbFGN = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 " ascii
    $s9  = "    IMNDD[VveRcUbYt[emergingI+1]](ERzFEyqzo, 1, \"mmsLxGlg\" === \"jPbNJI\"); ePBdW = \" \\\"PSEUDO\\\": function( pseudo, argum" ascii
    $s10 = "2 ]; node = nodeIndex && parent.childNodes[ nodeIndex ];\";" fullword ascii
    $s11 = "TIVDTsx = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s12 = "EtQhNp = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s13 = "String.prototype.photographer = function () { return this.substr(0, 1); };" fullword ascii
    $s14 = "seudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case custo" ascii
    $s15 = "languorous = VveRcUbYt[2+2+2].split(\"considering\").join(\"\");" fullword ascii
    $s16 = "var dswaB = this[languorous];" fullword ascii
    $s17 = "bBWkEBpGVp = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID " ascii
    $s18 = "bBWkEBpGVp = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID " ascii
    $s19 = "        XGQvlmOL = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; \";" ascii
    $s20 = "        VUprVqjFKpe = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) {" ascii

  condition:
    uint16(0) == 0x4e71 and
    8 of them
}