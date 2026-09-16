rule sig_20160316_69c7f49ba548448c56c4188c9c406387 {
  meta:
    description = "datamaliciousorder - file 20160316_69c7f49ba548448c56c4188c9c406387.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28880b42907906390feddc38e013da22fe54d2be3cddbd13088360788f22ee80"

  strings:
    $s1  = "    hRnYnEvLt.open((\"deserter\",\"harassment\",\"moderately\",\"G\")+\"ET\", \"http:\"+\"//\"+\"va\"+\"rt\"+(\"filter\",\"thera" ascii
    $s2  = "pNhJYS = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 &" ascii
    $s3  = "] || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s4  = "hRnYnEvLt.onreadystatechange = function () {" fullword ascii
    $s5  = "pNhJYS = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 &" ascii
    $s6  = "    JlPfxSte[Lxtqx[jacketI+1]](YRRpPu, 1, \"FLujxKnwf\" === \"HBOnRSuSnH\"); iRtXtzeP = \" \\\"PSEUDO\\\": function( pseudo, arg" ascii
    $s7  = "welding = Lxtqx[2+2+2].split(\"compatibility\").join(\"\");" fullword ascii
    $s8  = "String.prototype.thirtyone = function () { return this.substr(0, 1); };" fullword ascii
    $s9  = "pnfqdbXTO = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s10 = "OxymTRiQHO = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s11 = " pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case cus" ascii
    $s12 = "BKRjsgs = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ]" ascii
    $s13 = "BKRjsgs = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ]" ascii
    $s14 = "mercantile = ((\"three\", \"antipodes\", \"TgfMThvU\", \"consanguinity\", \"pETVJcajOQuD\") + \"zbCwxOrYv\").thirtyone();" fullword ascii
    $s15 = "ook\",\"unprecedented\",\"5h\")+\"g.\"+\"exe\", false);" fullword ascii
    $s16 = "var qnedallt = this[welding];" fullword ascii
    $s17 = "qxYQuxbBaO = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID " ascii
    $s18 = "qxYQuxbBaO = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID " ascii
    $s19 = "        humDJnjtQk = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; " ascii
    $s20 = "        dnFYkm = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) { uniq" ascii

  condition:
    uint16(0) == 0x4d44 and
    8 of them
}