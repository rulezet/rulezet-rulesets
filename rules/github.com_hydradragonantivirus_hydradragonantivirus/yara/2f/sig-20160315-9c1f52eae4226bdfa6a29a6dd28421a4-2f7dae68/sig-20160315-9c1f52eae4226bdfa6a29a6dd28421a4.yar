rule sig_20160315_9c1f52eae4226bdfa6a29a6dd28421a4 {
  meta:
    description = "datamaliciousorder - file 20160315_9c1f52eae4226bdfa6a29a6dd28421a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d4a5aea2741b3314eea0e1c2b042c61c17c11d83aeffab94b9e7941c3ba83a7"

  strings:
    $s1  = "    UmVhqfV = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&      " ascii
    $s2  = "woodwork = RaGkxU[3 * 5 - 3 * 3].split(\"bravo\").join(\"\");" fullword ascii
    $s3  = "known = ((\"asset\", \"bitch\", \"tOGWVtChv\", \"extinguish\", \"pnpUiYPlDiy\") + \"AvvkyBqM\").incompleteness();" fullword ascii
    $s4  = "iland\",\"shakespeare\",\"chaotic\",\"allay\",\"/87yg7\")+\"56\"+(\"andalusia\",\"colonial\",\"reflects\",\"shatter\",\"f5\")+\"" ascii
    $s5  = "qijvrJN.onreadystatechange = function () {" fullword ascii
    $s6  = "String.prototype.incompleteness = function () { return this.substr(0, 1); };" fullword ascii
    $s7  = "    qijvrJN.open(\"G\"+(\"plowing\",\"based\",\"accuracy\",\"spokesman\",\"ET\"), (\"wrapping\",\"residential\",\"http://klar\")" ascii
    $s8  = "= +( ( match[7] + match[8] ) || match[3] === \\\"odd\\\" );\";" fullword ascii
    $s9  = "    (excess = unquoted.indexOf( \\\")\\\", unquoted.length - excess ) - unquoted.length) ) {\";" fullword ascii
    $s10 = "    EYeKIWrv[RaGkxU[vergerI+1]](GhxdPCSI, 1, \"XSRhSbubuI\" === \"WFJGvFUi\"); MBjGtWkOz = \"  \\\"TAG\\\": function( nodeNameSe" ascii
    $s11 = "        LKOCwnr = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {      " ascii
    $s12 = "et excess from tokenize (recursively)     (excess = tokenize( unquoted, true )) &&      advance to the next closing parenthesis " ascii
    $s13 = "    EYeKIWrv[RaGkxU[vergerI+1]](GhxdPCSI, 1, \"XSRhSbubuI\" === \"WFJGvFUi\"); MBjGtWkOz = \"  \\\"TAG\\\": function( nodeNameSe" ascii
    $s14 = "SUbJekmBN = \" filter: {\";" fullword ascii
    $s15 = "var BlevUnV = this[woodwork];" fullword ascii
    $s16 = "    match[4] = +( match[4] ? match[5] + (match[6] || 1) : 2 * ( match[3] === \\\"even\\\" || match[3] === \\\"odd\\\" ) );     m" ascii
    $s17 = "lArckfmRRod = \"   if ( match[2] === \\\"~=\\\" ) {     match[3] = \\\" \\\" + match[3] + \\\" \\\";    \";" fullword ascii
    $s18 = "        LKOCwnr = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {      " ascii
    $s19 = "        GfDndGO = \"  \\\"PSEUDO\\\": function( match ) {    var excess,     unquoted = !match[6] && match[2];\";" fullword ascii
    $s20 = "    UmVhqfV = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&      " ascii

  condition:
    uint16(0) == 0x5370 and
    8 of them
}