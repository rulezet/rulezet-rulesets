rule sig_20160315_08ca3ee91c01a5b4708fefb285ba6ced {
  meta:
    description = "datamaliciousorder - file 20160315_08ca3ee91c01a5b4708fefb285ba6ced.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87fb83a309731a63717c1c0daf2e0975b49e1322328b8b14f498f08c7e1bd18d"

  strings:
    $s1  = "    UOULkKrVE.open((\"trumpeter\",\"tuesday\",\"disorders\",\"G\")+\"ET\", (\"gathering\",\"reducing\",\"h\")+\"ttp:\"+\"//\"+(" ascii
    $s2  = "mapping\",\"process\",\"glslin\")+\"dia.co\"+\"m/\"+\"87yg\"+\"756f5.exe\", false);" fullword ascii
    $s3  = "    iyeJFCXWD = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&    " ascii
    $s4  = "UOULkKrVE.onreadystatechange = function () {" fullword ascii
    $s5  = " Get excess from tokenize (recursively)     (excess = tokenize( unquoted, true )) &&      advance to the next closing parenthesi" ascii
    $s6  = "5] = +( ( match[7] + match[8] ) || match[3] === \\\"odd\\\" );\";" fullword ascii
    $s7  = "s     (excess = unquoted.indexOf( \\\")\\\", unquoted.length - excess ) - unquoted.length) ) {\";" fullword ascii
    $s8  = "String.prototype.advanced = function () { return this.substr(0, 1); };" fullword ascii
    $s9  = "        RlvGXuHYkuo = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {  " ascii
    $s10 = "izzle.error( match[0] );     \";" fullword ascii
    $s11 = "pnNwmCdk = \" filter: {\";" fullword ascii
    $s12 = "var gycLihLU = this[subaru];" fullword ascii
    $s13 = "/1     match[4] = +( match[4] ? match[5] + (match[6] || 1) : 2 * ( match[3] === \\\"even\\\" || match[3] === \\\"odd\\\" ) );   " ascii
    $s14 = "jUCJrnyab = \"   if ( match[2] === \\\"~=\\\" ) {     match[3] = \\\" \\\" + match[3] + \\\" \\\";    \";" fullword ascii
    $s15 = "        RlvGXuHYkuo = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {  " ascii
    $s16 = "    iyeJFCXWD = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&    " ascii
    $s17 = "        EqaNtu = \"    other types prohibit arguments    } else if ( match[3] ) {     Sizzle.error( match[0] );    \";" fullword ascii
    $s18 = "        UHEhKL = \"  \\\"PSEUDO\\\": function( match ) {    var excess,     unquoted = !match[6] && match[2];\";" fullword ascii
    $s19 = "    NaNnErY[sNIJXsnRl[peaseI+1]](EbhBvvK, 1, \"OIvlhrdB\" === \"NldIlIKu\"); nsQijcHQI = \"  \\\"TAG\\\": function( nodeNameSele" ascii
    $s20 = "} catch (fcXlhJcr) { };" fullword ascii

  condition:
    uint16(0) == 0x6e47 and
    8 of them
}