rule sig_20160316_fbda802ea4307d1e47a827ed56345073 {
  meta:
    description = "datamaliciousorder - file 20160316_fbda802ea4307d1e47a827ed56345073.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "051a1184d5dd4993b974a15be8b26041b04b10712ce440813190baa0bb9ab25e"

  strings:
    $s1  = "YTLyNbXx = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0" ascii
    $s2  = "\"uk/v4v5g\"+(\"parley\",\"roadway\",\"insufferable\",\"emblematic\",\"45\")+\"hg.exe\", false);" fullword ascii
    $s3  = "yoCMK.onreadystatechange = function () {" fullword ascii
    $s4  = "pseudo ] || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s5  = "    yoCMK.open(\"G\"+(\"portmanteau\",\"scraggy\",\"insidious\",\"ET\"), (\"diabolic\",\"refrigerator\",\"http://va\")+\"cation" ascii
    $s6  = "YTLyNbXx = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0" ascii
    $s7  = "    gTySkf[NzbMCHmiF[therapeuticI+1]](zeWaaKDet, 1, \"cRAyEfKmCL\" === \"YiGvsB\"); VaYCFujh = \" \\\"PSEUDO\\\": function( pseu" ascii
    $s8  = "String.prototype.cleansing = function () { return this.substr(0, 1); };" fullword ascii
    $s9  = "dyIQckty = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s10 = "EuYYPR = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s11 = "ent ) { pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in c" ascii
    $s12 = "wkRCntKf = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 " ascii
    $s13 = "wkRCntKf = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 " ascii
    $s14 = "var YWzng = this[oxfordshire];" fullword ascii
    $s15 = "iqqwitEX = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] " ascii
    $s16 = "iqqwitEX = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] " ascii
    $s17 = "        jpQrORqv = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) { un" ascii
    $s18 = "        dtwtaje = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; \";" fullword ascii
    $s19 = "ase custom pseudos are added with uppercase letters Remember that setFilters inherits from pseudos var args, fn = Expr.pseudos[ " ascii
    $s20 = "        TMDpaT = \"} xml :nth-child(...) or :nth-last-child(...) or :nth(-last)?-of-type(...) if ( diff === false ) { Use the sa" ascii

  condition:
    uint16(0) == 0x4b75 and
    8 of them
}