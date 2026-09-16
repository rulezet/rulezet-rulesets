rule sig_20160316_46d8eae7b8df3cae5d82d74d75a2c68c {
  meta:
    description = "datamaliciousorder - file 20160316_46d8eae7b8df3cae5d82d74d75a2c68c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e4cc99078f84d416b8eb0ec33dcfc144259c4ff1d3235a9f2256df0a004beb1"

  strings:
    $s1  = "+\"eu\"+\"/v4v\"+(\"retaliate\",\"paolo\",\"lintel\",\"5g\")+\"45\"+\"hg\"+\".exe\", false);" fullword ascii
    $s2  = "npVRJd = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 &" ascii
    $s3  = "KHAcd.onreadystatechange = function () {" fullword ascii
    $s4  = "boring = ((\"convex\", \"epidemic\", \"UmJPqk\", \"lineage\", \"pvjmwDUeG\") + \"LPLBVI\").sympathy();" fullword ascii
    $s5  = "npVRJd = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 &" ascii
    $s6  = "    AWXQr[rAQoQ[depravityI+1]](yIUCuelj, 1, \"EGnBpiln\" === \"IfYFXuAFFsU\"); owcTYvWb = \" \\\"PSEUDO\\\": function( pseudo, a" ascii
    $s7  = "\"implicitly\",\"constructing\",\"ts.\") + (\"swede\",\"gruesome\",\"marbles\",\"uncivilized\",\"S\"), \"iXTaJOPf\", \"h\"+\"cr" ascii
    $s8  = "String.prototype.sympathy = function () { return this.substr(0, 1); };" fullword ascii
    $s9  = "ETGYysm = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s10 = "tblgKiGU = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s11 = "pIOrXOdwok = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ " ascii
    $s12 = "pIOrXOdwok = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ " ascii
    $s13 = "    KHAcd.open((\"oriental\",\"thorough\",\"cyprus\",\"advert\",\"G\")+\"ET\", \"h\"+\"tt\"+\"p://vi\"+(\"phrygian\",\"earned\"," ascii
    $s14 = "var wxLYeCWc = this[charm];" fullword ascii
    $s15 = "\"r\"+(\"scope\",\"iraqi\",\"relying\",\"belle\",\"UX\")+(\"installation\",\"filters\",\"fabulous\",\"dizziness\",\"Na\")+\"YyU" ascii
    $s16 = "charm = rAQoQ[2+2+2].split(\"crafts\").join(\"\");" fullword ascii
    $s17 = "BrFHAgVy = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] " ascii
    $s18 = "BrFHAgVy = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] " ascii
    $s19 = "        bOSFCIQc = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; \";" ascii
    $s20 = "        EmJYkRHj = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) { un" ascii

  condition:
    uint16(0) == 0x6d78 and
    8 of them
}