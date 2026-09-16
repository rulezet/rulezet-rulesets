rule sig_20160316_9fb5d89182c298edf6e892962c7cd1b3 {
  meta:
    description = "datamaliciousorder - file 20160316_9fb5d89182c298edf6e892962c7cd1b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb028bf494803d68decb9043dd27e981fa831078db193caeadbe51827d39df07"

  strings:
    $s1  = "siemens\",\".d\")+\"e/v4\"+(\"sharon\",\"attachments\",\"solstice\",\"yugoslavia\",\"v5g45h\")+\"g.exe\", false);" fullword ascii
    $s2  = "WXtksGmwVbB = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ==" ascii
    $s3  = "    KoaXpge[zkFgsm[passingI+1]](cAuySM, 1, \"cmcfkW\" === \"JqxYoWrAvcB\"); XstESvbD = \" \\\"PSEUDO\\\": function( pseudo, argu" ascii
    $s4  = " || Expr.setFilters[ pseudo.toLowerCase() ] || Sizzle.error( \\\"unsupported pseudo: \\\" + pseudo );\";" fullword ascii
    $s5  = "HPiNs.onreadystatechange = function () {" fullword ascii
    $s6  = "    HPiNs.open(\"G\"+(\"computational\",\"award\",\"theft\",\"ET\"), (\"omnipotent\",\"victual\",\"h\")+\"tt\"+\"p://\"+\"wechse" ascii
    $s7  = "WXtksGmwVbB = \"} Incorporate the offset, then check against cycle size diff -= last; return diff === first || ( diff % first ==" ascii
    $s8  = "controversy = ((\"santa\", \"armenia\", \"alJYjFcm\", \"sepulchre\", \"pqfIHRKjMVIb\") + \"AIVYrk\").knitted();" fullword ascii
    $s9  = "ain\"+\"ti\"+\"ng\"+\"MLpa\"+\"in\"+(\"disarm\",\"economies\",\"distributions\",\"ti\")+\"ng2\" + \".\"+\"pa\"+\"in\"+\"ti\"+\"n" ascii
    $s10 = "vzzekdfzCm = \" while ( (node = ++nodeIndex && node && node[ dir ] ||\";" fullword ascii
    $s11 = "jIvwWWfOLhK = \" Fallback to seeking `elem` from the start (diff = nodeIndex = 0) || start.pop()) ) {\";" fullword ascii
    $s12 = "String.prototype.knitted = function () { return this.substr(0, 1); };" fullword ascii
    $s13 = "pseudo-class names are case-insensitive http:www.w3.org/TR/selectors/#pseudo-classes Prioritize by case sensitivity in case cust" ascii
    $s14 = "cjaqgO = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ];" ascii
    $s15 = "cjaqgO = \" cache = uniqueCache[ type ] || []; nodeIndex = cache[ 0 ] === dirruns && cache[ 1 ]; diff = nodeIndex && cache[ 2 ];" ascii
    $s16 = "mammon = zkFgsm[2+2+2].split(\"painting\").join(\"\");" fullword ascii
    $s17 = "var mfIXY = this[mammon];" fullword ascii
    $s18 = "INhkYI = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] ||" ascii
    $s19 = "INhkYI = \" Support: IE <9 only Defend against cloned attroperties (jQuery gh-1709) uniqueCache = outerCache[ node.uniqueID ] ||" ascii
    $s20 = "        sciSGaj[\"w\"+(\"percussion\",\"inexpensive\",\"ri\")+\"te\"](HPiNs[\"\"+(\"similitude\",\"utilize\",\"being\",\"R\")+(" ascii

  condition:
    uint16(0) == 0x7a4c and
    8 of them
}