rule sig_20160316_3ceceb2c7ca1788d246b9f0c2c4fbbe3 {
  meta:
    description = "datamaliciousorder - file 20160316_3ceceb2c7ca1788d246b9f0c2c4fbbe3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4012f8377cf98c4e7a4e899d7b23fff0abcd65cf15442cc48a8a2b5e427aaf1"

  strings:
    $s1  = "physiognomy = ((\"squint\", \"login\", \"zHaGKu\", \"manatarms\", \"pLOuJcGUsREw\") + \"rSGEfJvIo\").shares();" fullword ascii
    $s2  = "yCKlElt = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 " ascii
    $s3  = "sHlUHS.onreadystatechange = function () {" fullword ascii
    $s4  = "String.prototype.shares = function () { return this.substr(0, 1); };" fullword ascii
    $s5  = "    WXvoscjRM[KcNvoD[admissionsI+1]](FtInrRwW, 1, \"cJWnzmURe\" === \"NdgYIgw\"); PBUby = \" \\\"PSEUDO\\\": function( pseudo, a" ascii
    $s6  = "yCKlElt = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 " ascii
    $s7  = "ecSDHnMnYW = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s8  = "FrjNsEUwUN = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s9  = "    sHlUHS.open((\"shareholders\",\"infra\",\"lunch\",\"G\")+\"ET\", (\"wellington\",\"vehicles\",\"immune\",\"h\")+(\"saturday" ascii
    $s10 = "lleWJE = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ];" ascii
    $s11 = "lleWJE = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ];" ascii
    $s12 = "tesimal\",\"tudor\",\"recognised\",\"hg\")+(\"spence\",\"tardiness\",\".e\")+\"xe\", false);" fullword ascii
    $s13 = "var JHMtHXRoQ = this[ticked];" fullword ascii
    $s14 = "ticked = KcNvoD[2+2+2].split(\"robert\").join(\"\");" fullword ascii
    $s15 = "be\"+(\"deployment\",\"alumni\",\"kinship\",\"rt\")+\"Ob\"+\"ro\"+\"bertjerobe\"+\"rt\"+\"ct\", \"WuYiMJCy\", \"JiLoVfAvlP\", (" ascii
    $s16 = "leasure\",\"immediately\",\"J\")+\"HG\"+\"sy\"+(\"misuse\",\"tanzania\",\"FNzC\"), (\"instance\",\"speaking\",\"M\")+\"robert\"+" ascii
    $s17 = "mswsrf = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] ||" ascii
    $s18 = "mswsrf = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] ||" ascii
    $s19 = "        TxFjJnFlpl = \" When found, cache indexes on `parent` and break if ( node.nodeType === 1 && ++diff && node === elem ) { " ascii
    $s20 = "        hNpqjP = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex; \";" fullword ascii

  condition:
    uint16(0) == 0x5869 and
    8 of them
}