rule sig_20160316_3aa6d8e8fab10acc18cb3267376f9606 {
  meta:
    description = "datamaliciousorder - file 20160316_3aa6d8e8fab10acc18cb3267376f9606.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "343d42f628da2f56569d8a2e07efdf6773ae7d3535cdef8d45b5649b437b0081"

  strings:
    $s1  = "    lvzhX.open((\"creating\",\"fathers\",\"G\")+\"ET\", (\"boatswain\",\"fitting\",\"h\")+(\"unfaithful\",\"completeness\",\"tt" ascii
    $s2  = "king\",\"5g\")+\"45\"+(\"forming\",\"chorus\",\"incumbent\",\"hg\")+(\"workshop\",\"belize\",\"mustang\",\".exe\"), false);" fullword ascii
    $s3  = "oEcsgW = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 &" ascii
    $s4  = "lvzhX.onreadystatechange = function () {" fullword ascii
    $s5  = "nv\")+\"ir\"+(\"deflected\",\"firemen\",\"on\")+(\"belated\",\"changelog\",\"me\")+\"ntStri\"+\"ngs\", (\"possession\",\"unstabl" ascii
    $s6  = "oEcsgW = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 &" ascii
    $s7  = "    WCklOPf[DTdoffqgk[toolbarI+1]](GfJrOQtej, 1, \"RCTfJYY\" === \"HwioEem\"); MlqHdXaU = \" \\\"PSEUDO\\\": function( pseudo, a" ascii
    $s8  = "]; node = nodeIndex && parent.childNodes[ nodeIndex ];\";" fullword ascii
    $s9  = "zxHeqKbiF = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s10 = "String.prototype.venomous = function () { return this.substr(0, 1); };" fullword ascii
    $s11 = "PykMUMjF = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s12 = "KzHAJkKsO = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2" ascii
    $s13 = "KzHAJkKsO = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2" ascii
    $s14 = "decline = DTdoffqgk[2+2+2].split(\"intellectually\").join(\"\");" fullword ascii
    $s15 = "var EEvRlkw = this[decline];" fullword ascii
    $s16 = "WhGIefu = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] |" ascii
    $s17 = "WhGIefu = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] |" ascii
    $s18 = "    lvzhX.open((\"creating\",\"fathers\",\"G\")+\"ET\", (\"boatswain\",\"fitting\",\"h\")+(\"unfaithful\",\"completeness\",\"tt" ascii
    $s19 = "        KObtpXETreY = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; " ascii
    $s20 = "        iBmPmuQ = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) { uni" ascii

  condition:
    uint16(0) == 0x5741 and
    8 of them
}