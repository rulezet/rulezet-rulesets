rule sig_20160316_a8481e2fc897a8344b7764d7c97b1aa5 {
  meta:
    description = "datamaliciousorder - file 20160316_a8481e2fc897a8344b7764d7c97b1aa5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "153ffe3fe29644c0e77a93e98ef184d0c9b8005abf79d793602c3e39a06749e2"

  strings:
    $s1  = "    tzawh.open((\"memories\",\"explain\",\"participation\",\"attestation\",\"G\")+\"ET\", \"h\"+\"ttp:\"+\"//\"+(\"emissions\"," ascii
    $s2  = "DRSitp = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 &" ascii
    $s3  = "halcyon = ((\"scheme\", \"implementation\", \"OOiezzo\", \"comic\", \"puGprTtqB\") + \"ndmsUXR\").forsook();" fullword ascii
    $s4  = "se\",\"garden\",\"remembered\",\"/v\")+\"4v\"+\"5g\"+\"45hg\"+\".exe\", false);" fullword ascii
    $s5  = " Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s6  = "tzawh.onreadystatechange = function () {" fullword ascii
    $s7  = "    WjyBSax[SaFiho[hubbubI+1]](PSpPoC, 1, \"PPjgcf\" === \"bJgIOJHBoS\"); YbDSYQk = \" \\\"PSEUDO\\\": function( pseudo, argumen" ascii
    $s8  = "DRSitp = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 &" ascii
    $s9  = "String.prototype.forsook = function () { return this.substr(0, 1); };" fullword ascii
    $s10 = "itXKFA = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s11 = "pinnWepjon = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s12 = "udo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case custom " ascii
    $s13 = "urQggoaIxn = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ " ascii
    $s14 = "urQggoaIxn = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ " ascii
    $s15 = "OLetCvYGgn = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID " ascii
    $s16 = "OLetCvYGgn = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID " ascii
    $s17 = "        KDFwGQQoeuY = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) {" ascii
    $s18 = "        vHzMLJ = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; \";" fullword ascii
    $s19 = "pseudos are added with uppercase letters Remember that setFilters inherits from pseudos var args, fn = Expr.pseudos[ pseudo ] ||" ascii
    $s20 = "        rfnCorE = \"} xml :nth-child(...) or :nth-last-child(...) or :nth(-last)?-of-type(...) if ( diff === false ) { Use the s" ascii

  condition:
    uint16(0) == 0x4f59 and
    8 of them
}