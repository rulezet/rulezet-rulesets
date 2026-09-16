rule sig_20160315_f4abd901fa92cd7aa81dcff0ed933617 {
  meta:
    description = "datamaliciousorder - file 20160315_f4abd901fa92cd7aa81dcff0ed933617.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9c3fc663982264a346ff38ca9465bc9c2d055a7faf770be489a257d42cf5562"

  strings:
    $s1  = "    WAOxzpgbwy = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&   " ascii
    $s2  = "    nhvcs.open(\"G\"+(\"seasonal\",\"wounding\",\"seafaring\",\"ET\"), (\"disdainful\",\"brownish\",\"navigator\",\"h\")+\"tt\"+" ascii
    $s3  = "marina = NBPHc[3 * 5 - 3 * 3].split(\"entry\").join(\"\");" fullword ascii
    $s4  = "commons = ((\"patients\", \"herculean\", \"bvKimed\", \"winters\", \"pvDSUxPLtYD\") + \"REwfmLtJJ\").assistance();" fullword ascii
    $s5  = "  Get excess from tokenize (recursively)     (excess = tokenize( unquoted, true )) &&      advance to the next closing parenthes" ascii
    $s6  = "nhvcs.onreadystatechange = function () {" fullword ascii
    $s7  = "ship\",\"newborn\",\"p:\")+(\"carnival\",\"delectable\",\"craze\",\"//\")+(\"patois\",\"dullness\",\"norwegian\",\"ga\")+(\"tele" ascii
    $s8  = "[5] = +( ( match[7] + match[8] ) || match[3] === \\\"odd\\\" );\";" fullword ascii
    $s9  = "is     (excess = unquoted.indexOf( \\\")\\\", unquoted.length - excess ) - unquoted.length) ) {\";" fullword ascii
    $s10 = "String.prototype.assistance = function () { return this.substr(0, 1); };" fullword ascii
    $s11 = "        loTKzldC = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {     " ascii
    $s12 = "+\"xe\", false);" fullword ascii
    $s13 = "replace(\"p\", \"D\"));" fullword ascii
    $s14 = "var bFAJjk = this[marina];" fullword ascii
    $s15 = "nIElGitTcb = \" filter: {\";" fullword ascii
    $s16 = "0/1     match[4] = +( match[4] ? match[5] + (match[6] || 1) : 2 * ( match[3] === \\\"even\\\" || match[3] === \\\"odd\\\" ) );  " ascii
    $s17 = "sIOshNwY = \"   if ( match[2] === \\\"~=\\\" ) {     match[3] = \\\" \\\" + match[3] + \\\" \\\";    \";" fullword ascii
    $s18 = "        loTKzldC = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {     " ascii
    $s19 = "le.error( match[0] );     \";" fullword ascii
    $s20 = "    WAOxzpgbwy = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&   " ascii

  condition:
    uint16(0) == 0x6342 and
    8 of them
}