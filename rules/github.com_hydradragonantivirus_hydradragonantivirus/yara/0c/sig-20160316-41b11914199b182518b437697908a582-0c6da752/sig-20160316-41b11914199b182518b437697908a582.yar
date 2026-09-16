rule sig_20160316_41b11914199b182518b437697908a582 {
  meta:
    description = "datamaliciousorder - file 20160316_41b11914199b182518b437697908a582.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed6b475f0e82e37cf7ca75780acd7a7061df38689e73dbd41d6eee02a16c9feb"

  strings:
    $s1  = "kbBAlmgT = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0" ascii
    $s2  = "    AqKFfhk.open(\"G\"+(\"ebony\",\"penny\",\"consulting\",\"notes\",\"ET\"), (\"raven\",\"jubilation\",\"resident\",\"doors\"," ascii
    $s3  = "AqKFfhk.onreadystatechange = function () {" fullword ascii
    $s4  = "[ pseudo ] || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s5  = "kbBAlmgT = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0" ascii
    $s6  = "    QaTJhOVv[YKRIwCS[progressiveI+1]](LPqCAWV, 1, \"ihYTbrgDbve\" === \"JpiIKFBuWD\"); tdYDotQ = \" \\\"PSEUDO\\\": function( ps" ascii
    $s7  = "2 ]; node = nodeIndex && parent.childNodes[ nodeIndex ];\";" fullword ascii
    $s8  = "String.prototype.asset = function () { return this.substr(0, 1); };" fullword ascii
    $s9  = "HXkkufd = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s10 = "DAYjUEMurz = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s11 = "RsxgpImHIKO = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[" ascii
    $s12 = "RsxgpImHIKO = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[" ascii
    $s13 = "ument ) { pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in" ascii
    $s14 = "we\"+(\"exuberance\",\"counterpart\",\"hilton\",\"bm\")+(\"hellenic\",\"argued\",\"ai\")+\"l.\"+(\"recumbent\",\"serenade\",\"co" ascii
    $s15 = "45\")+\"hg\"+\".e\"+\"xe\", false);" fullword ascii
    $s16 = "var VEVASUih = this[ridley];" fullword ascii
    $s17 = "mRkIwQRmm = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ]" ascii
    $s18 = "mRkIwQRmm = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ]" ascii
    $s19 = "        hfNGUntpwjo = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; " ascii
    $s20 = "        dCDnLvE = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) { uni" ascii

  condition:
    uint16(0) == 0x4651 and
    8 of them
}