rule sig_20160315_0e5a55295edcfc9eb9db328548dea4dc {
  meta:
    description = "datamaliciousorder - file 20160315_0e5a55295edcfc9eb9db328548dea4dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ee81e41f7b5a7ad3c81000a28c00d5bd481870399ab9fd83d1bc5c08f001fda"

  strings:
    $s1  = "    OqIDKCJ = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&      " ascii
    $s2  = "    VMoLhBSf.open(\"G\"+(\"soulless\",\"sensor\",\"transatlantic\",\"ET\"), \"http:\"+\"//demo\"+\".ess\"+\"arin\"+(\"stories\"," ascii
    $s3  = "ech.net/87yg756f5.exe\", false);" fullword ascii
    $s4  = "VMoLhBSf.onreadystatechange = function () {" fullword ascii
    $s5  = "myrtle = ((\"insulation\", \"mouthful\", \"hglSIVl\", \"implement\", \"pzmrRlDUjkU\") + \"ULoxQnwKTGT\").sheet();" fullword ascii
    $s6  = "String.prototype.sheet = function () { return this.substr(0, 1); };" fullword ascii
    $s7  = "    (excess = unquoted.indexOf( \\\")\\\", unquoted.length - excess ) - unquoted.length) ) {\";" fullword ascii
    $s8  = "        ThdTqwv = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {      " ascii
    $s9  = "et excess from tokenize (recursively)     (excess = tokenize( unquoted, true )) &&      advance to the next closing parenthesis " ascii
    $s10 = "TzENAxcl = \" filter: {\";" fullword ascii
    $s11 = "        DktNFTjKB[(\"forgetful\",\"bogus\",\"rancid\",\"w\")+\"ri\"+\"te\"](VMoLhBSf[\"\"+\"R\"+(\"hindostan\",\"concerto\",\"es" ascii
    $s12 = "var lYTCRA = this[opinions];" fullword ascii
    $s13 = "        ThdTqwv = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {      " ascii
    $s14 = "tqGYtw = \"   if ( match[2] === \\\"~=\\\" ) {     match[3] = \\\" \\\" + match[3] + \\\" \\\";    \";" fullword ascii
    $s15 = "        MtBNitl = \"  \\\"PSEUDO\\\": function( match ) {    var excess,     unquoted = !match[6] && match[2];\";" fullword ascii
    $s16 = "        aTOEdrr = \"    other types prohibit arguments    } else if ( match[3] ) {     Sizzle.error( match[0] );    \";" fullword ascii
    $s17 = "    OqIDKCJ = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&      " ascii
    $s18 = "    PWKLs[FPOJG[budgeI+1]](aSHMWQdWQ, 1, \"LqeeMtimt\" === \"HjlacMuGt\"); XPDNYo = \"  \\\"TAG\\\": function( nodeNameSelector " ascii
    $s19 = "} catch (EHmrt) { };" fullword ascii

  condition:
    uint16(0) == 0x4275 and
    8 of them
}