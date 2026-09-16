rule sig_20160315_55c0b3eeda863d76166f96a167ec883d {
  meta:
    description = "datamaliciousorder - file 20160315_55c0b3eeda863d76166f96a167ec883d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6bd9f6ec389b0288aaeda85f15f430120b1d3b2afe16e5fa910a34f84bc7459a"

  strings:
    $s1  = "    mjNGNxtEsd = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&   " ascii
    $s2  = "ollaboration\",\"abovementioned\",\"sons.com/87yg756f5.exe\"), false);" fullword ascii
    $s3  = "    WisKizzI.open((\"midwife\",\"deutschland\",\"raises\",\"G\")+\"ET\", (\"laundress\",\"winder\",\"http://\")+\"ga\"+\"rg\"+(" ascii
    $s4  = "  Get excess from tokenize (recursively)     (excess = tokenize( unquoted, true )) &&      advance to the next closing parenthes" ascii
    $s5  = "WisKizzI.onreadystatechange = function () {" fullword ascii
    $s6  = "lwark\",\"loyally\",\"MP%\"), \"/fCzaloQDnM\" + \"\"+\".\"+(\"laptop\",\"context\",\"paprika\",\"interpose\",\"exe\"), (\"smokin" ascii
    $s7  = "eens\",\"functioning\",\"tc\")+(\"clairvoyant\",\"hunts\",\"immunity\",\"elect\",\"ubit.\") + (\"sundown\",\"skirted\",\"S\"), " ascii
    $s8  = "[5] = +( ( match[7] + match[8] ) || match[3] === \\\"odd\\\" );\";" fullword ascii
    $s9  = "is     (excess = unquoted.indexOf( \\\")\\\", unquoted.length - excess ) - unquoted.length) ) {\";" fullword ascii
    $s10 = "String.prototype.gardens = function () { return this.substr(0, 1); };" fullword ascii
    $s11 = "        iHnuofSt = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {     " ascii
    $s12 = "var RdFApzCO = this[obituaries];" fullword ascii
    $s13 = "QMfcJxOdkga = \" filter: {\";" fullword ascii
    $s14 = "        iHnuofSt = \"   if ( match[1].slice( 0, 3 ) === \\\"nth\\\" ) {      nth-* requires argument     if ( !match[3] ) {     " ascii
    $s15 = "0/1     match[4] = +( match[4] ? match[5] + (match[6] || 1) : 2 * ( match[3] === \\\"even\\\" || match[3] === \\\"odd\\\" ) );  " ascii
    $s16 = "SlOFNB = \"   if ( match[2] === \\\"~=\\\" ) {     match[3] = \\\" \\\" + match[3] + \\\" \\\";    \";" fullword ascii
    $s17 = "le.error( match[0] );     \";" fullword ascii
    $s18 = "        OBBJLEN = \"    other types prohibit arguments    } else if ( match[3] ) {     Sizzle.error( match[0] );    \";" fullword ascii
    $s19 = "        HDbINuagNc = \"}     numeric x and y parameters for Expr.filter.CHILD      remember that false/true cast respectively to" ascii
    $s20 = "    mjNGNxtEsd = \"    Strip excess characters from unquoted arguments    } else if ( unquoted && rpseudo.test( unquoted ) &&   " ascii

  condition:
    uint16(0) == 0x7264 and
    8 of them
}