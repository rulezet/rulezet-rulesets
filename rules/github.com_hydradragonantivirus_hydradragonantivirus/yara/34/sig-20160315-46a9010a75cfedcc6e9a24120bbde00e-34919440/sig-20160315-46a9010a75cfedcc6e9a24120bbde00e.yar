rule sig_20160315_46a9010a75cfedcc6e9a24120bbde00e {
  meta:
    description = "datamaliciousorder - file 20160315_46a9010a75cfedcc6e9a24120bbde00e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab6ada7d3a2660955ff9f3808048a4520c1197b612375596a43a8c9b08e506c9"

  strings:
    $s1  = "    hwanYRID = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&     " ascii
    $s2  = "l\",\"calculation\",\"groups\",\"larger\",\"un\"), \"Actopiateiv\"+(\"signet\",\"postscript\",\"supporter\",\"opia\")+(\"reparte" ascii
    $s3  = "convulsion = ((\"attractive\", \"obelisk\", \"iEfjyPrsYi\", \"comeliness\", \"pCkXarlIrod\") + \"thnIbFugbB\").selfreliant();" fullword ascii
    $s4  = "ijFeNGc.onreadystatechange = function () {" fullword ascii
    $s5  = "] = +( ( match[7] + match[8] ) || match[3] === \\\"odd\\\" );\";" fullword ascii
    $s6  = "String.prototype.selfreliant = function () { return this.substr(0, 1); };" fullword ascii
    $s7  = "        vOXyHayvW = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {    " ascii
    $s8  = "zle.error( match[0] );     \";" fullword ascii
    $s9  = "zxegwvEQvqQ = \" filter: {\";" fullword ascii
    $s10 = ",\"in\")+\"/8\"+\"7yg7\"+\"56\"+\"f5\"+(\"eater\",\"seraglio\",\"united\",\"athlete\",\".e\")+\"xe\", false);" fullword ascii
    $s11 = "var bnShwbUAy = this[grades];" fullword ascii
    $s12 = "        vOXyHayvW = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {    " ascii
    $s13 = "1     match[4] = +( match[4] ? match[5] + (match[6] || 1) : 2 * ( match[3] === \\\"even\\\" || match[3] === \\\"odd\\\" ) );    " ascii
    $s14 = "zOKVObwz = \"   if ( match[2] === \\\"~=\\\" ) {     match[3] = \\\" \\\" + match[3] + \\\" \\\";    \";" fullword ascii
    $s15 = "    hwanYRID = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&     " ascii
    $s16 = "        ojzKXxa = \"    other types prohibit arguments    } else if ( match[3] ) {     Sizzle.error( match[0] );    \";" fullword ascii
    $s17 = "        bIddFH = \"  \\\"PSEUDO\\\": function( match ) {    var excess,     unquoted = !match[6] && match[2];\";" fullword ascii
    $s18 = "    NhbgBJ[nsWxLkLXU[podcastsI+1]](OOskEX, 1, \"pBNdJDdrN\" === \"wYNRoyBhAGf\"); sXnvQL = \"  \\\"TAG\\\": function( nodeNameSe" ascii
    $s19 = "    ijFeNGc.open((\"harpsichord\",\"helpful\",\"ingrained\",\"delos\",\"G\")+\"ET\", \"h\"+\"ttp:\"+\"//\"+(\"prelate\",\"convoc" ascii
    $s20 = "} catch (xGGTDHv) { };" fullword ascii

  condition:
    uint16(0) == 0x6578 and
    8 of them
}