rule sig_20160315_33f8e79a20775d54bf69b878da3db40f {
  meta:
    description = "datamaliciousorder - file 20160315_33f8e79a20775d54bf69b878da3db40f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea8bdc59eed8324e706edbaefb2ba984357ad687f13fe24392fe22b0b892c736"

  strings:
    $s1  = "    RKyQAathJ = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&    " ascii
    $s2  = "gainsay = pjvqqlW[3 * 5 - 3 * 3].split(\"advertise\").join(\"\");" fullword ascii
    $s3  = " Get excess from tokenize (recursively)     (excess = tokenize( unquoted, true )) &&      advance to the next closing parenthesi" ascii
    $s4  = "CsFymwHGk.onreadystatechange = function () {" fullword ascii
    $s5  = "= +( ( match[7] + match[8] ) || match[3] === \\\"odd\\\" );\";" fullword ascii
    $s6  = "    CsFymwHGk.open(\"G\"+(\"persuasive\",\"humanitarian\",\"ET\"), \"h\"+\"tt\"+\"p:\"+\"//\"+\"cr\"+(\"chaplet\",\"kneeled\",\"" ascii
    $s7  = "s     (excess = unquoted.indexOf( \\\")\\\", unquoted.length - excess ) - unquoted.length) ) {\";" fullword ascii
    $s8  = "String.prototype.hesse = function () { return this.substr(0, 1); };" fullword ascii
    $s9  = "\"wa\"+\"ll\"+(\"oncoming\",\"mediocre\",\"et.n\")+\"et\"+\"/8\"+\"7y\"+\"g7\"+\"56f5\"+\".e\"+\"xe\", false);" fullword ascii
    $s10 = "        UTNBiQ = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {      S" ascii
    $s11 = "var ixNnGWeAD = this[gainsay];" fullword ascii
    $s12 = "artistic = ((\"instances\", \"disprove\", \"uqKcay\", \"meter\", \"pXoozKUsvuu\") + \"vMQubEAkvXJ\").hesse();" fullword ascii
    $s13 = "HuGNoQfYtlp = \" filter: {\";" fullword ascii
    $s14 = "    match[4] = +( match[4] ? match[5] + (match[6] || 1) : 2 * ( match[3] === \\\"even\\\" || match[3] === \\\"odd\\\" ) );     m" ascii
    $s15 = "ohdYTSlY = \"   if ( match[2] === \\\"~=\\\" ) {     match[3] = \\\" \\\" + match[3] + \\\" \\\";    \";" fullword ascii
    $s16 = "        UTNBiQ = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {      S" ascii
    $s17 = ".error( match[0] );     \";" fullword ascii
    $s18 = "    RKyQAathJ = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&    " ascii
    $s19 = "        EQBjYSkG = \"  \\\"PSEUDO\\\": function( match ) {    var excess,     unquoted = !match[6] && match[2];\";" fullword ascii
    $s20 = "        xvDUHoxtbc = \"    other types prohibit arguments    } else if ( match[3] ) {     Sizzle.error( match[0] );    \";" fullword ascii

  condition:
    uint16(0) == 0x667a and
    8 of them
}