rule sig_20160316_606112d339e0e0afbabeaf8128cb4581 {
  meta:
    description = "datamaliciousorder - file 20160316_606112d339e0e0afbabeaf8128cb4581.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b73692e48c05cbfe6881615807007d766954759131a67ea199a73411818ec8cd"

  strings:
    $s1  = "\",\"p:\")+\"//\"+\"vartasha\"+\"kti.co\"+\"m/\"+\"v4\"+(\"media\",\"louise\",\"v5g4\")+\"5h\"+\"g.exe\", false);" fullword ascii
    $s2  = "    kSqUgM.open(\"G\"+(\"turned\",\"palatine\",\"seafood\",\"ET\"), (\"intimidation\",\"transparent\",\"installations\",\"htt\")" ascii
    $s3  = "eredKn = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 &" ascii
    $s4  = "r.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s5  = "kSqUgM.onreadystatechange = function () {" fullword ascii
    $s6  = "eredKn = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 &" ascii
    $s7  = "    bLDavsU[AOceqN[beatlesI+1]](glYcA, 1, \"tGlIfN\" === \"YOtMBnQP\"); UUXzA = \" \\\"PSEUDO\\\": function( pseudo, argument ) " ascii
    $s8  = "specialist = ((\"ensemble\", \"mural\", \"tLVBLuSuh\", \"relay\", \"pQndwPSTF\") + \"WNQaeKjSlgi\").romance();" fullword ascii
    $s9  = "2 ]; node = nodeIndex && parent.childNodes[ nodeIndex ];\";" fullword ascii
    $s10 = "String.prototype.romance = function () { return this.substr(0, 1); };" fullword ascii
    $s11 = "yOoFvFayz = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s12 = "vlLkIzkhx = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s13 = "class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case custom pseu" ascii
    $s14 = "vNukGUFJFwk = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[" ascii
    $s15 = "vNukGUFJFwk = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[" ascii
    $s16 = "romance()]();" fullword ascii
    $s17 = "(\"blond\",\"harass\",\"shack\",\"\")+\"%\"+\"TE\"+\"MP%\", \"/mzYgqh\" + \"\"+(\"lucca\",\"swerve\",\"asking\",\".\")+\"exe\", " ascii
    $s18 = "swJLXFui = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] " ascii
    $s19 = "swJLXFui = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] " ascii
    $s20 = "        IxQgWwGVF = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) { u" ascii

  condition:
    uint16(0) == 0x6966 and
    8 of them
}