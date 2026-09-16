rule sig_20160315_9c09f11180419052433831515a600dbe {
  meta:
    description = "datamaliciousorder - file 20160315_9c09f11180419052433831515a600dbe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af06572506329051713a7e8b26208803841585fc35cca4ebb6d123393e10507d"

  strings:
    $s1  = "    zwhbUznVd = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&    " ascii
    $s2  = "inelegant = eaCmrQ[3 * 5 - 3 * 3].split(\"antarctic\").join(\"\");" fullword ascii
    $s3  = "    xEltohgn.open(\"G\"+(\"fiftytwo\",\"undergrowth\",\"appealingly\",\"weeding\",\"ET\"), (\"defines\",\"spoilt\",\"colour\",\"" ascii
    $s4  = "apers\",\"molest\",\"pedestrian\",\"orchid\",\"/87y\")+(\"blockhouse\",\"rhythm\",\"g756f5.exe\"), false);" fullword ascii
    $s5  = " Get excess from tokenize (recursively)     (excess = tokenize( unquoted, true )) &&      advance to the next closing parenthesi" ascii
    $s6  = "xEltohgn.onreadystatechange = function () {" fullword ascii
    $s7  = "s     (excess = unquoted.indexOf( \\\")\\\", unquoted.length - excess ) - unquoted.length) ) {\";" fullword ascii
    $s8  = "String.prototype.reference = function () { return this.substr(0, 1); };" fullword ascii
    $s9  = "        VybueBME = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {     " ascii
    $s10 = "var FpOJz = this[inelegant];" fullword ascii
    $s11 = "cOTeSMjI = \" filter: {\";" fullword ascii
    $s12 = "        VybueBME = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {     " ascii
    $s13 = "DibAxFIKq = \"   if ( match[2] === \\\"~=\\\" ) {     match[3] = \\\" \\\" + match[3] + \\\" \\\";    \";" fullword ascii
    $s14 = "le.error( match[0] );     \";" fullword ascii
    $s15 = "        lsdahOJpe = \"  \\\"PSEUDO\\\": function( match ) {    var excess,     unquoted = !match[6] && match[2];\";" fullword ascii
    $s16 = "        iIzfVGdGs = \"    other types prohibit arguments    } else if ( match[3] ) {     Sizzle.error( match[0] );    \";" fullword ascii
    $s17 = "    zwhbUznVd = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&    " ascii
    $s18 = "    feovhYKQ[eaCmrQ[entreeI+1]](uTkIN, 1, \"tXvFXzn\" === \"GbzKfnHtr\"); lDYPrG = \"  \\\"TAG\\\": function( nodeNameSelector )" ascii
    $s19 = "} catch (gibsvhJD) { };" fullword ascii

  condition:
    uint16(0) == 0x6d4b and
    8 of them
}