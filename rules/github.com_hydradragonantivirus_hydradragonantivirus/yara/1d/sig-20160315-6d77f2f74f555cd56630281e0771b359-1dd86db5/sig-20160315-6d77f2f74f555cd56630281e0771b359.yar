rule sig_20160315_6d77f2f74f555cd56630281e0771b359 {
  meta:
    description = "datamaliciousorder - file 20160315_6d77f2f74f555cd56630281e0771b359.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31ecf85994b857b7e580f1db9c52002d70d59a4a904d1428783fe9eb14a73deb"

  strings:
    $s1  = "    yBxHvmOaGh = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&   " ascii
    $s2  = "  Get excess from tokenize (recursively)     (excess = tokenize( unquoted, true )) &&      advance to the next closing parenthes" ascii
    $s3  = "ySfMuPvf.onreadystatechange = function () {" fullword ascii
    $s4  = "h[5] = +( ( match[7] + match[8] ) || match[3] === \\\"odd\\\" );\";" fullword ascii
    $s5  = "referee = ((\"belarus\", \"rambling\", \"wgnutn\", \"frontier\", \"pFQQixvX\") + \"lzqBwazv\").fortyseven();" fullword ascii
    $s6  = "is     (excess = unquoted.indexOf( \\\")\\\", unquoted.length - excess ) - unquoted.length) ) {\";" fullword ascii
    $s7  = "String.prototype.fortyseven = function () { return this.substr(0, 1); };" fullword ascii
    $s8  = "        CSAhHqaBIB = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {   " ascii
    $s9  = "zzle.error( match[0] );     \";" fullword ascii
    $s10 = "even()]();" fullword ascii
    $s11 = "var DdMbAI = this[awestruck];" fullword ascii
    $s12 = " 0/1     match[4] = +( match[4] ? match[5] + (match[6] || 1) : 2 * ( match[3] === \\\"even\\\" || match[3] === \\\"odd\\\" ) ); " ascii
    $s13 = "\"payments\",\"g7\")+\"56\"+(\"emanation\",\"author\",\"f5\")+\".e\"+(\"cannonade\",\"responses\",\"holdings\",\"xe\"), false);" fullword ascii
    $s14 = "WFgzSKUnHa = \"   if ( match[2] === \\\"~=\\\" ) {     match[3] = \\\" \\\" + match[3] + \\\" \\\";    \";" fullword ascii
    $s15 = "        CSAhHqaBIB = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {   " ascii
    $s16 = "        pgzjLJb = \"    other types prohibit arguments    } else if ( match[3] ) {     Sizzle.error( match[0] );    \";" fullword ascii
    $s17 = "    yBxHvmOaGh = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&   " ascii
    $s18 = "        lmIYmdarSxB = \"  \\\"PSEUDO\\\": function( match ) {    var excess,     unquoted = !match[6] && match[2];\";" fullword ascii
    $s19 = "    bcraoF[oWsozGor[metaphoricalI+1]](kkmkweF, 1, \"NjujDSeq\" === \"ejISGkxhm\"); DTVMoxFVD = \"  \\\"TAG\\\": function( nodeNa" ascii
    $s20 = "} catch (TJeBjCoWL) { };" fullword ascii

  condition:
    uint16(0) == 0x5741 and
    8 of them
}