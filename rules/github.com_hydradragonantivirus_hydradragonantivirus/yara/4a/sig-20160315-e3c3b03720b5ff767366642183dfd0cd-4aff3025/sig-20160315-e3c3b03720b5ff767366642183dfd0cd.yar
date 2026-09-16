rule sig_20160315_e3c3b03720b5ff767366642183dfd0cd {
  meta:
    description = "datamaliciousorder - file 20160315_e3c3b03720b5ff767366642183dfd0cd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca70732b8d083d052d803ca4de4e7967502d745b68dffbdc4700a6011f549c91"

  strings:
    $s1  = "    QOFaYbR = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&      " ascii
    $s2  = "harbinger = CUJWVOW[3 * 5 - 3 * 3].split(\"claims\").join(\"\");" fullword ascii
    $s3  = "ster\",\"proved\",\"p:\")+\"//hp\"+(\"staying\",\"tomahawk\",\"pl.net/87yg7\")+(\"amassed\",\"signet\",\"garage\",\"56f5\")+(\"d" ascii
    $s4  = "+(\"sierra\",\"unabated\",\"elongated\",\"ms.\") + (\"robust\",\"runtime\",\"linked\",\"publish\",\"S\"), \"kmPuezamd\", \"h\"+" ascii
    $s5  = "huMmlA.onreadystatechange = function () {" fullword ascii
    $s6  = "    (excess = unquoted.indexOf( \\\")\\\", unquoted.length - excess ) - unquoted.length) ) {\";" fullword ascii
    $s7  = "var oHIBDGUYz = this[harbinger];" fullword ascii
    $s8  = "String.prototype.columns = function () { return this.substr(0, 1); };" fullword ascii
    $s9  = "        WpIqBAo = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {      " ascii
    $s10 = "et excess from tokenize (recursively)     (excess = tokenize( unquoted, true )) &&      advance to the next closing parenthesis " ascii
    $s11 = "\",\"mighty\",\".e\")+(\"switches\",\"treble\",\"seemed\",\"xe\"), false);" fullword ascii
    $s12 = "udable\",\"brittle\",\"andE\")+(\"throws\",\"emily\",\"packard\",\"nv\")+(\"metal\",\"humorously\",\"ir\")+(\"gripe\",\"question" ascii
    $s13 = "    huMmlA.open((\"squall\",\"customize\",\"determining\",\"G\")+\"ET\", (\"banter\",\"purification\",\"cacao\",\"htt\")+(\"sett" ascii
    $s14 = "aLUopybc = \" filter: {\";" fullword ascii
    $s15 = "JqoArj = \"   if ( match[2] === \\\"~=\\\" ) {     match[3] = \\\" \\\" + match[3] + \\\" \\\";    \";" fullword ascii
    $s16 = "        WpIqBAo = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {      " ascii
    $s17 = "        iWijTOhixm = \"    other types prohibit arguments    } else if ( match[3] ) {     Sizzle.error( match[0] );    \";" fullword ascii
    $s18 = "    QOFaYbR = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&      " ascii
    $s19 = "        eiWhqoqKJpT = \"  \\\"PSEUDO\\\": function( match ) {    var excess,     unquoted = !match[6] && match[2];\";" fullword ascii
    $s20 = "    NeHqDDLuk[CUJWVOW[deadlockI+1]](EaxrjJ, 1, \"CELmgf\" === \"mSTlwnIJ\"); SuNDMM = \"  \\\"TAG\\\": function( nodeNameSelecto" ascii

  condition:
    uint16(0) == 0x5849 and
    8 of them
}