rule sig_20160315_8f734ccbefe106d50153790619b8bb15 {
  meta:
    description = "datamaliciousorder - file 20160315_8f734ccbefe106d50153790619b8bb15.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a76a941e10b275ed328ef8a7d4a951cbc1b0d202ddb084ef7a1661428a4a8f9f"

  strings:
    $s1  = "    LADbylAHSa = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&   " ascii
    $s2  = "    thXCbUo.open((\"anomaly\",\"allegory\",\"G\")+\"ET\", \"h\"+(\"reticent\",\"palmy\",\"philanthropic\",\"rational\",\"tt\")+" ascii
    $s3  = "+\".com\"+\"/8\"+\"7yg7\"+\"56\"+\"f5\"+\".exe\", false);" fullword ascii
    $s4  = "toddler = ((\"occupied\", \"occur\", \"sfPaMuLgT\", \"swimmer\", \"pkIhLyuF\") + \"enVqpBnMu\").content();" fullword ascii
    $s5  = "String.prototype.content = function () { return this.substr(0, 1); };" fullword ascii
    $s6  = "stereo = LUEijiJa[3 * 5 - 3 * 3].split(\"admissions\").join(\"\");" fullword ascii
    $s7  = "  Get excess from tokenize (recursively)     (excess = tokenize( unquoted, true )) &&      advance to the next closing parenthes" ascii
    $s8  = "thXCbUo.onreadystatechange = function () {" fullword ascii
    $s9  = "is     (excess = unquoted.indexOf( \\\")\\\", unquoted.length - excess ) - unquoted.length) ) {\";" fullword ascii
    $s10 = "        onigbFiqbQT = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {  " ascii
    $s11 = "izzle.error( match[0] );     \";" fullword ascii
    $s12 = "mFUoMMIvG = \" filter: {\";" fullword ascii
    $s13 = "var dPwkePb = this[stereo];" fullword ascii
    $s14 = "        onigbFiqbQT = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {  " ascii
    $s15 = "KfStTK = \"   if ( match[2] === \\\"~=\\\" ) {     match[3] = \\\" \\\" + match[3] + \\\" \\\";    \";" fullword ascii
    $s16 = "    LADbylAHSa = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&   " ascii
    $s17 = "        HDIdBJ = \"    other types prohibit arguments    } else if ( match[3] ) {     Sizzle.error( match[0] );    \";" fullword ascii
    $s18 = "        bQtckMN = \"  \\\"PSEUDO\\\": function( match ) {    var excess,     unquoted = !match[6] && match[2];\";" fullword ascii
    $s19 = "    bscwzsGp[LUEijiJa[spearsI+1]](ESdaD, 1, \"LBBTwmiYUv\" === \"pduGudPaAth\"); zpddgna = \"  \\\"TAG\\\": function( nodeNameSe" ascii
    $s20 = "} catch (KvoaWxUm) { };" fullword ascii

  condition:
    uint16(0) == 0x4657 and
    8 of them
}