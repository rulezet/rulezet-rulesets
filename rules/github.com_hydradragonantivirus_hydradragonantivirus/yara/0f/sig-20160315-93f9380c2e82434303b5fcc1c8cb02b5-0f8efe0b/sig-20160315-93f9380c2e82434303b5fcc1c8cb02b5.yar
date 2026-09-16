rule sig_20160315_93f9380c2e82434303b5fcc1c8cb02b5 {
  meta:
    description = "datamaliciousorder - file 20160315_93f9380c2e82434303b5fcc1c8cb02b5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b46008a1c8a5f22a70bb5f7434a48149043a7a465884bab86a340968c339f5e7"

  strings:
    $s1  = "    XtcFRlRiN = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&    " ascii
    $s2  = "    WCOduIGg.open((\"limousines\",\"lakes\",\"G\")+\"ET\", (\"beautiful\",\"plane\",\"daddy\",\"broadway\",\"h\")+(\"lasso\",\"c" ascii
    $s3  = "7yg756\"+\"f5.exe\", false);" fullword ascii
    $s4  = " Get excess from tokenize (recursively)     (excess = tokenize( unquoted, true )) &&      advance to the next closing parenthesi" ascii
    $s5  = "WCOduIGg.onreadystatechange = function () {" fullword ascii
    $s6  = "h[5] = +( ( match[7] + match[8] ) || match[3] === \\\"odd\\\" );\";" fullword ascii
    $s7  = "loathing = ((\"expiring\", \"invective\", \"rkBochhvdD\", \"incorporation\", \"pHzAhOS\") + \"STAPnNwhd\").irreverent();" fullword ascii
    $s8  = "shank = FWULoSGc[3 * 5 - 3 * 3].split(\"castaway\").join(\"\");" fullword ascii
    $s9  = "s     (excess = unquoted.indexOf( \\\")\\\", unquoted.length - excess ) - unquoted.length) ) {\";" fullword ascii
    $s10 = "String.prototype.irreverent = function () { return this.substr(0, 1); };" fullword ascii
    $s11 = "        hWFnjMJOadS = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {  " ascii
    $s12 = "izzle.error( match[0] );     \";" fullword ascii
    $s13 = "var LBXYTw = this[shank];" fullword ascii
    $s14 = "BAtwlaEx = \" filter: {\";" fullword ascii
    $s15 = " 0/1     match[4] = +( match[4] ? match[5] + (match[6] || 1) : 2 * ( match[3] === \\\"even\\\" || match[3] === \\\"odd\\\" ) ); " ascii
    $s16 = "        hWFnjMJOadS = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {  " ascii
    $s17 = "oejhAYEvFxd = \"   if ( match[2] === \\\"~=\\\" ) {     match[3] = \\\" \\\" + match[3] + \\\" \\\";    \";" fullword ascii
    $s18 = "        mluOFhPk = \"  \\\"PSEUDO\\\": function( match ) {    var excess,     unquoted = !match[6] && match[2];\";" fullword ascii
    $s19 = "        KCYrmpjPLHp = \"    other types prohibit arguments    } else if ( match[3] ) {     Sizzle.error( match[0] );    \";" fullword ascii
    $s20 = "    XtcFRlRiN = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&    " ascii

  condition:
    uint16(0) == 0x6f57 and
    8 of them
}