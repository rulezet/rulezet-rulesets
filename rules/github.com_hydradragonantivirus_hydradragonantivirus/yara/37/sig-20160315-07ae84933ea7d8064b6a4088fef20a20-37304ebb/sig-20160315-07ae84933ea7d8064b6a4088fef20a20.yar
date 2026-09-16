rule sig_20160315_07ae84933ea7d8064b6a4088fef20a20 {
  meta:
    description = "datamaliciousorder - file 20160315_07ae84933ea7d8064b6a4088fef20a20.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95b893894943e729ebcb76316c4ed7735e001c3f39fbf036cbb98ae22f2f0e1c"

  strings:
    $s1  = "    UYiDlleITP = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&   " ascii
    $s2  = "surge = iypKVDHwA[3 * 5 - 3 * 3].split(\"bilious\").join(\"\");" fullword ascii
    $s3  = "  Get excess from tokenize (recursively)     (excess = tokenize( unquoted, true )) &&      advance to the next closing parenthes" ascii
    $s4  = "gsUdhpta.onreadystatechange = function () {" fullword ascii
    $s5  = "is     (excess = unquoted.indexOf( \\\")\\\", unquoted.length - excess ) - unquoted.length) ) {\";" fullword ascii
    $s6  = "String.prototype.fallacy = function () { return this.substr(0, 1); };" fullword ascii
    $s7  = "    UYiDlleITP = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&   " ascii
    $s8  = "        uicnnY = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {      S" ascii
    $s9  = "    gsUdhpta.open((\"dildos\",\"molecules\",\"actuated\",\"G\")+\"ET\", \"htt\"+(\"butterfly\",\"billiard\",\"output\",\"p:\")+" ascii
    $s10 = "var AmPCPVfl = this[surge];" fullword ascii
    $s11 = "mMKvDf = \" filter: {\";" fullword ascii
    $s12 = "in/87yg7\"+\"56f5.e\"+\"xe\", false);" fullword ascii
    $s13 = "        uicnnY = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {      S" ascii
    $s14 = "UmbCyb = \"   if ( match[2] === \\\"~=\\\" ) {     match[3] = \\\" \\\" + match[3] + \\\" \\\";    \";" fullword ascii
    $s15 = "        SgcOyPO = \"    other types prohibit arguments    } else if ( match[3] ) {     Sizzle.error( match[0] );    \";" fullword ascii
    $s16 = "        YzdsxPsyW = \"  \\\"PSEUDO\\\": function( match ) {    var excess,     unquoted = !match[6] && match[2];\";" fullword ascii
    $s17 = ".error( match[0] );     \";" fullword ascii
    $s18 = "    yrRBkPFO[iypKVDHwA[soldieryI+1]](QqmJsd, 1, \"VuTfegpYGX\" === \"BwCrlVVqkm\"); OJCjiDiX = \"  \\\"TAG\\\": function( nodeNa" ascii
    $s19 = "} catch (AvDsQS) { };" fullword ascii

  condition:
    uint16(0) == 0x4978 and
    8 of them
}