rule sig_20160315_ada8c00ae395b90676c8a79b4ac613bc {
  meta:
    description = "datamaliciousorder - file 20160315_ada8c00ae395b90676c8a79b4ac613bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d403ce0a99398828dc539cb67babc4c376d3308d824e5a11d467163ff23a4ec"

  strings:
    $s1  = "    vnuLODTbzQY = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&  " ascii
    $s2  = "dependence = OfJmwjxR[3 * 5 - 3 * 3].split(\"fiber\").join(\"\");" fullword ascii
    $s3  = "   Get excess from tokenize (recursively)     (excess = tokenize( unquoted, true )) &&      advance to the next closing parenthe" ascii
    $s4  = "dBsHQonMQ.onreadystatechange = function () {" fullword ascii
    $s5  = "] = +( ( match[7] + match[8] ) || match[3] === \\\"odd\\\" );\";" fullword ascii
    $s6  = "\")+\"cz/87y\"+\"g7\"+(\"erotic\",\"bracken\",\"abdicate\",\"56f5.exe\"), false);" fullword ascii
    $s7  = "String.prototype.suffolk = function () { return this.substr(0, 1); };" fullword ascii
    $s8  = "sis     (excess = unquoted.indexOf( \\\")\\\", unquoted.length - excess ) - unquoted.length) ) {\";" fullword ascii
    $s9  = "        DQabtD = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {      S" ascii
    $s10 = "    dBsHQonMQ.open(\"G\"+(\"rearguard\",\"expire\",\"counseling\",\"ET\"), (\"detriment\",\"struct\",\"arrears\",\"illegitimate" ascii
    $s11 = "detention = ((\"notification\", \"manuals\", \"PfnRWn\", \"prolix\", \"pbitSYrrw\") + \"DLeRNjKVcAs\").suffolk();" fullword ascii
    $s12 = "l\",\"relfib\")+(\"zambia\",\"departure\",\"primeval\",\"erl\"), \"CqOaQlFnJ\", \"\"+\"w\"+(\"boxes\",\"helen\",\"mutter\",\"YD" ascii
    $s13 = "jYnbiSfctrq = \" filter: {\";" fullword ascii
    $s14 = "var AzIFnR = this[dependence];" fullword ascii
    $s15 = "1     match[4] = +( match[4] ? match[5] + (match[6] || 1) : 2 * ( match[3] === \\\"even\\\" || match[3] === \\\"odd\\\" ) );    " ascii
    $s16 = "        DQabtD = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {      S" ascii
    $s17 = "QQIMvNK = \"   if ( match[2] === \\\"~=\\\" ) {     match[3] = \\\" \\\" + match[3] + \\\" \\\";    \";" fullword ascii
    $s18 = ".error( match[0] );     \";" fullword ascii
    $s19 = "        NGGhGs = \"    other types prohibit arguments    } else if ( match[3] ) {     Sizzle.error( match[0] );    \";" fullword ascii
    $s20 = "        AIDEjM = \"  \\\"PSEUDO\\\": function( match ) {    var excess,     unquoted = !match[6] && match[2];\";" fullword ascii

  condition:
    uint16(0) == 0x7470 and
    8 of them
}