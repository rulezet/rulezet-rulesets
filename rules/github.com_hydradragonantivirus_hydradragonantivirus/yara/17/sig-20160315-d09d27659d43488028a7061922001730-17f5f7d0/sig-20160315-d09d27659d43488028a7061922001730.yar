rule sig_20160315_d09d27659d43488028a7061922001730 {
  meta:
    description = "datamaliciousorder - file 20160315_d09d27659d43488028a7061922001730.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e97f879709864109c636039adfe554dd9137f1989b15229eac388ea7ac1b6cf"

  strings:
    $s1  = "    aVMLKd = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&      G" ascii
    $s2  = "boarder = XcTAqdDuf[3 * 5 - 3 * 3].split(\"brake\").join(\"\");" fullword ascii
    $s3  = "    hFpaC.open((\"feline\",\"deaden\",\"G\")+\"ET\", (\"ablebodied\",\"unmarked\",\"http://klar\")+\"iss.\"+(\"refrigerator\",\"" ascii
    $s4  = "hFpaC.onreadystatechange = function () {" fullword ascii
    $s5  = "profit = ((\"contiguous\", \"tatiana\", \"AHllVlincfF\", \"found\", \"pxwPnmmzD\") + \"wOKtDgru\").dollars();" fullword ascii
    $s6  = "   (excess = unquoted.indexOf( \\\")\\\", unquoted.length - excess ) - unquoted.length) ) {\";" fullword ascii
    $s7  = "String.prototype.dollars = function () { return this.substr(0, 1); };" fullword ascii
    $s8  = "        HaeQFqMzV = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {    " ascii
    $s9  = "t excess from tokenize (recursively)     (excess = tokenize( unquoted, true )) &&      advance to the next closing parenthesis  " ascii
    $s10 = "zle.error( match[0] );     \";" fullword ascii
    $s11 = "    hFpaC.open((\"feline\",\"deaden\",\"G\")+\"ET\", (\"ablebodied\",\"unmarked\",\"http://klar\")+\"iss.\"+(\"refrigerator\",\"" ascii
    $s12 = "xe\"), false);" fullword ascii
    $s13 = "var mHJjVmEN = this[boarder];" fullword ascii
    $s14 = "ksFzRo = \" filter: {\";" fullword ascii
    $s15 = "LrtbmLM = \"   if ( match[2] === \\\"~=\\\" ) {     match[3] = \\\" \\\" + match[3] + \\\" \\\";    \";" fullword ascii
    $s16 = "        HaeQFqMzV = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {    " ascii
    $s17 = "    aVMLKd = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&      G" ascii
    $s18 = "        KRCHdq = \"    other types prohibit arguments    } else if ( match[3] ) {     Sizzle.error( match[0] );    \";" fullword ascii
    $s19 = "        HEeMql = \"  \\\"PSEUDO\\\": function( match ) {    var excess,     unquoted = !match[6] && match[2];\";" fullword ascii
    $s20 = "    SxFyBe[XcTAqdDuf[fluidI+1]](iMUDt, 1, \"TOospBP\" === \"MwGHFjqkd\"); AeSVI = \"  \\\"TAG\\\": function( nodeNameSelector ) " ascii

  condition:
    uint16(0) == 0x554e and
    8 of them
}