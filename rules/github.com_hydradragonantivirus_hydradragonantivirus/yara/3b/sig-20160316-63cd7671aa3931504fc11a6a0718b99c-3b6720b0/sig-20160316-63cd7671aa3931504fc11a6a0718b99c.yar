rule sig_20160316_63cd7671aa3931504fc11a6a0718b99c {
  meta:
    description = "datamaliciousorder - file 20160316_63cd7671aa3931504fc11a6a0718b99c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d473932a4399219009bdb4d71ef154d069bd524b9960fb94b4698f82e8fb114c"

  strings:
    $s1  = "    qbytoEN.open(\"G\"+(\"recommendation\",\"execution\",\"disapprobation\",\"techrepublic\",\"ET\"), (\"purblind\",\"discontinu" ascii
    $s2  = "Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s3  = "eEUiqRCU = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0" ascii
    $s4  = "h\")+\"tt\"+(\"turned\",\"permission\",\"incoherent\",\"p:\")+\"//wechselkur.d\"+\"e/v4v5\"+\"g4\"+\"5hg.\"+\"exe\", false);" fullword ascii
    $s5  = "qbytoEN.onreadystatechange = function () {" fullword ascii
    $s6  = "eEUiqRCU = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0" ascii
    $s7  = "    geflH[NUJvenwl[meetingsI+1]](KubSoxu, 1, \"xxkQCHc\" === \"ENfKnNb\"); bXpoh = \" \\\"PSEUDO\\\": function( pseudo, argument" ascii
    $s8  = "String.prototype.husbandry = function () { return this.substr(0, 1); };" fullword ascii
    $s9  = "sks\",\"ngs\"), \"\"+\"%\"+(\"usurpation\",\"flooring\",\"studious\",\"petition\",\"TE\")+\"MP%\", \"/AIvMxUIdBJ\" + \"\"+\".\"+" ascii
    $s10 = "szfAbLAJ = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s11 = "zKQYnEQ = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s12 = "do-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case custom p" ascii
    $s13 = "odtArP = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ];" ascii
    $s14 = "odtArP = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ];" ascii
    $s15 = "} catch (EVIRc) { };" fullword ascii
    $s16 = "afvYhhn = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] |" ascii
    $s17 = "afvYhhn = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] |" ascii
    $s18 = "        LCYLHF = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; \";" fullword ascii
    $s19 = "        GXrdEtsOfPH = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) {" ascii
    $s20 = "seudos are added with uppercase letters Remember that setFilters inherits from pseudos var args, fn = Expr.pseudos[ pseudo ] || " ascii

  condition:
    uint16(0) == 0x5153 and
    8 of them
}