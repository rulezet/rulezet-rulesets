rule sig_20160316_8772cab83ed85947abdfd3326a555ba8 {
  meta:
    description = "datamaliciousorder - file 20160316_8772cab83ed85947abdfd3326a555ba8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "543565e533350ae9a7239653f7a80e5d5bdbaa014bb4f8fdfbdd06cea3242a14"

  strings:
    $s1  = "    iOwbItE.open((\"bulletin\",\"adding\",\"fireman\",\"devising\",\"G\")+\"ET\", \"h\"+\"tt\"+(\"abdicate\",\"darius\",\"corset" ascii
    $s2  = "String.prototype.eyewitness = function () { return this.substr(0, 1); };" fullword ascii
    $s3  = "QJkvFgI = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 " ascii
    $s4  = "| Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s5  = "iOwbItE.onreadystatechange = function () {" fullword ascii
    $s6  = "brett = ((\"cultural\", \"coffer\", \"NONCaqAT\", \"walnut\", \"pzEUTAXxQrM\") + \"UXcxinnuKg\").eyewitness();" fullword ascii
    $s7  = "QJkvFgI = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first === 0 " ascii
    $s8  = "    EvWMdW[YFxaItxA[unmarkedI+1]](HRNCNY, 1, \"SXjRoe\" === \"cjjTHwuF\"); pSNltJz = \" \\\"PSEUDO\\\": function( pseudo, argume" ascii
    $s9  = "]; node = nodeIndex && parent.childNodes[ nodeIndex ];\";" fullword ascii
    $s10 = "emrUFhb = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s11 = "DzeUWeWPLu = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s12 = "eudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case custom" ascii
    $s13 = "hLdBHFHUE = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2" ascii
    $s14 = "hLdBHFHUE = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2" ascii
    $s15 = "shorter = YFxaItxA[2+2+2].split(\"halfbrother\").join(\"\");" fullword ascii
    $s16 = "var YFxaItxA = [\"WAq\"+(\"soliloquy\",\"wakes\",\"subsides\",\"considerable\",\"IH\")+\"GI\"+\"Vh\", \"Mfs\"+\"DM\"+\"FI\"+\"Bp" ascii
    $s17 = "e\", false);" fullword ascii
    $s18 = "\",\"bearable\",\"LV\"), \"E\"+\"xpan\"+\"dEnv\"+\"ir\"+\"on\"+\"me\"+(\"diadem\",\"beaches\",\"converge\",\"nt\")+\"St\"+\"ri\"" ascii
    $s19 = "var DIutS = this[shorter];" fullword ascii
    $s20 = "wKmUqJapgK = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID " ascii

  condition:
    uint16(0) == 0x5856 and
    8 of them
}