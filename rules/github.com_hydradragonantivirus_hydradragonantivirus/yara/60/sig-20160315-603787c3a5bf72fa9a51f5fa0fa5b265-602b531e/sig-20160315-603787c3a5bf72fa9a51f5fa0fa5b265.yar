rule sig_20160315_603787c3a5bf72fa9a51f5fa0fa5b265 {
  meta:
    description = "datamaliciousorder - file 20160315_603787c3a5bf72fa9a51f5fa0fa5b265.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1bbfe56b54336890dd42a796406653a3290294c09b17c07adc086d4f928fc432"

  strings:
    $s1  = "brand = jlEArNPyF[3 * 5 - 3 * 3].split(\"executives\").join(\"\");" fullword ascii
    $s2  = "String.prototype.processors = function () { return this.substr(0, 1); };" fullword ascii
    $s3  = "    HuSoMUCq = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&     " ascii
    $s4  = "spaniel = ((\"suffocate\", \"earning\", \"ltYzbES\", \"linux\", \"pPfzAIN\") + \"bVMIOQtndvC\").processors();" fullword ascii
    $s5  = "    bEOMf.open(\"G\"+(\"imperturbable\",\"unhealthy\",\"sewage\",\"spectacular\",\"ET\"), \"h\"+\"ttp:\"+(\"excellence\",\"often" ascii
    $s6  = "livestock\",\"/8\")+\"7y\"+(\"cossack\",\"accepts\",\"g756f5.exe\"), false);" fullword ascii
    $s7  = "bEOMf.onreadystatechange = function () {" fullword ascii
    $s8  = "5] = +( ( match[7] + match[8] ) || match[3] === \\\"odd\\\" );\";" fullword ascii
    $s9  = "nt\",\"sepulture\",\"cobweb\",\"trainer\",\"esSX\")+(\"naturals\",\"addiction\",\"ex\")+\"ec\"+(\"portmanteau\",\"cracker\",\"im" ascii
    $s10 = "        rtBRurHUVwP = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {  " ascii
    $s11 = "izzle.error( match[0] );     \";" fullword ascii
    $s12 = "var UTnAXYK = this[brand];" fullword ascii
    $s13 = "mzsqVrW = \" filter: {\";" fullword ascii
    $s14 = "/1     match[4] = +( match[4] ? match[5] + (match[6] || 1) : 2 * ( match[3] === \\\"even\\\" || match[3] === \\\"odd\\\" ) );   " ascii
    $s15 = "        rtBRurHUVwP = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {  " ascii
    $s16 = "jpMRdXb = \"   if ( match[2] === \\\"~=\\\" ) {     match[3] = \\\" \\\" + match[3] + \\\" \\\";    \";" fullword ascii
    $s17 = "        oSYapghTLBB = \"  \\\"PSEUDO\\\": function( match ) {    var excess,     unquoted = !match[6] && match[2];\";" fullword ascii
    $s18 = "    HuSoMUCq = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&     " ascii
    $s19 = "        DJLnMkJxE = \"    other types prohibit arguments    } else if ( match[3] ) {     Sizzle.error( match[0] );    \";" fullword ascii
    $s20 = "    lYWoxit[jlEArNPyF[evacuationI+1]](tVzxkL, 1, \"KGwzJnzFuC\" === \"JILCpnxv\"); XUkjNl = \"  \\\"TAG\\\": function( nodeNameS" ascii

  condition:
    uint16(0) == 0x506b and
    8 of them
}