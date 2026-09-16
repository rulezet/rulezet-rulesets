rule sig_20160316_1ba2bae52892adf66b1b38cdc6a34a03 {
  meta:
    description = "datamaliciousorder - file 20160316_1ba2bae52892adf66b1b38cdc6a34a03.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a0f7a6fe26f83963a5d86597b8bd274609bb40f762d28d479a62926fb5847fd"

  strings:
    $s1  = "ster\",\"li\")+(\"oblivious\",\"ethnic\",\"customers\",\"funeral\",\"ty\")+(\"evaporation\",\"processes\",\"iv\")+\"mo\"+\"bi\"+" ascii
    $s2  = "\",\"unfashionable\",\"palliate\",\"45\")+\"hg.exe\", false);" fullword ascii
    $s3  = "EXkpIOs = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 " ascii
    $s4  = "andria\",\"nagasaki\",\"lymph\",\"p://vacati\")+(\"creates\",\"ovary\",\"onin\")+\"bath.com/v4v\"+(\"edited\",\"closer\",\"homel" ascii
    $s5  = "wUGJSS.onreadystatechange = function () {" fullword ascii
    $s6  = "udo ] || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s7  = "    QNcynV[JXUIIyGCf[definitionsI+1]](vWOvLuopd, 1, \"KYoEEBO\" === \"nxkeeRCaY\"); uOCwB = \" \\\"PSEUDO\\\": function( pseudo," ascii
    $s8  = "EXkpIOs = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 " ascii
    $s9  = "AhxmRk = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s10 = "String.prototype.stunning = function () { return this.substr(0, 1); };" fullword ascii
    $s11 = "LfQEadmiuI = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s12 = "vbSVCIBM = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 " ascii
    $s13 = "vbSVCIBM = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 " ascii
    $s14 = " ) { pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case" ascii
    $s15 = "    wUGJSS.open((\"outweigh\",\"vastness\",\"cabaret\",\"G\")+\"ET\", \"h\"+(\"sweets\",\"printed\",\"clerk\",\"clearance\",\"tt" ascii
    $s16 = "var JSVSwE = this[peripherals];" fullword ascii
    $s17 = "bi\"+\"li\"+(\"sparrow\",\"provender\",\"fastidious\",\"ty\")+\"XMmobi\"+(\"obituary\",\"astronomy\",\"lity\")+\"LH\"+\"mo\"+(\"" ascii
    $s18 = "imperfection = ((\"madhouse\", \"landscape\", \"iDtOtQKz\", \"drill\", \"plIBUduYDc\") + \"gKKctbkYbt\").stunning();" fullword ascii
    $s19 = "ovBlnAaLb = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ]" ascii
    $s20 = "ovBlnAaLb = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ]" ascii

  condition:
    uint16(0) == 0x6446 and
    8 of them
}