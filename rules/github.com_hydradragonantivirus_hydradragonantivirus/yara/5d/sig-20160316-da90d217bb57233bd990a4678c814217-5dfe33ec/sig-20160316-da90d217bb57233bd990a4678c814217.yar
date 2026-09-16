rule sig_20160316_da90d217bb57233bd990a4678c814217 {
  meta:
    description = "datamaliciousorder - file 20160316_da90d217bb57233bd990a4678c814217.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f21289f2059ec2c335890362faf1282efd52b4ebac615f8c5fc191e4c3b5cf42"

  strings:
    $s1  = "ynpRheEdc = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === " ascii
    $s2  = "opportunity = ((\"wesley\", \"retrieved\", \"aXpyvIXhUS\", \"collector\", \"pAUgDMiy\") + \"HuyBftRkVgj\").realize();" fullword ascii
    $s3  = "r.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s4  = "qqdDwXNVf.onreadystatechange = function () {" fullword ascii
    $s5  = "    xxnMxK[BBscyHJK[slowlyI+1]](qxTTBo, 1, \"aueNdM\" === \"NCBucX\"); YiiINa = \" \\\"PSEUDO\\\": function( pseudo, argument ) " ascii
    $s6  = "ynpRheEdc = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === " ascii
    $s7  = "lr\"+(\"ought\",\"harem\",\"ip\")+\"tv\"+\"entral.\" + (\"mostly\",\"cronies\",\"dissection\",\"detraction\",\"S\"), \"KNPjXgU\"" ascii
    $s8  = "XjoTPdCk = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s9  = "TdOixQnCqz = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s10 = "String.prototype.realize = function () { return this.substr(0, 1); };" fullword ascii
    $s11 = "class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case custom pseu" ascii
    $s12 = "KuHChV = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ];" ascii
    $s13 = "KuHChV = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ];" ascii
    $s14 = "    qqdDwXNVf.open(\"G\"+(\"pension\",\"unwashed\",\"colossus\",\"competition\",\"ET\"), (\"delight\",\"threshold\",\"h\")+\"ttp" ascii
    $s15 = "var QyzMsxH = this[forge];" fullword ascii
    $s16 = "\",\"hve\")+\"nt\"+\"ra\"+\"lelv\"+(\"ninetynine\",\"bleaching\",\"scout\",\"scenic\",\"en\")+\"trall\", \"mcVqkNfDxq\", \"v\"+" ascii
    $s17 = "forge = BBscyHJK[2+2+2].split(\"ventral\").join(\"\");" fullword ascii
    $s18 = "tEdREBV = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] |" ascii
    $s19 = "tEdREBV = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] |" ascii
    $s20 = "        IYjxQDbR = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) { un" ascii

  condition:
    uint16(0) == 0x6978 and
    8 of them
}