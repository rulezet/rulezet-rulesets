rule sig_20160315_b2ff94fe0ab11172a8ff22e2677476a1 {
  meta:
    description = "datamaliciousorder - file 20160315_b2ff94fe0ab11172a8ff22e2677476a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27a287f45567100c37b3fd615dcb1d4b51cd66a347e378a6ffadf807f0ff9d64"

  strings:
    $s1  = "operator === \\\"$=\\\" ? check && result.slice( -check.length ) === check :      operator === \\\"~=\\\" ? ( \\\" \\\" + result" ascii
    $s2  = "        MwMzsUX = \"    return operator === \\\"=\\\" ? result === check :      operator === \\\"!=\\\" ? result !== check :    " ascii
    $s3  = "royal = dnTyVmH[3 * 5 - 3 * 3].split(\"hanging\").join(\"\");" fullword ascii
    $s4  = "hitespace, \\\" \\\" ) + \\\" \\\" ).indexOf( check ) > -1 :      operator === \\\"|=\\\" ? result === check || result.slice( 0," ascii
    $s5  = "r === \\\"^=\\\" ? check && result.indexOf( check ) === 0 :      operator === \\\"*=\\\" ? check && result.indexOf( check ) > -1" ascii
    $s6  = "COKxMaBnW.onreadystatechange = function () {" fullword ascii
    $s7  = "     forward = type.slice( -4 ) !== \\\"last\\\",     ofType = what === \\\"of-type\\\";\";" fullword ascii
    $s8  = "        RGiHOBfW = \"  \\\"CHILD\\\": function( type, what, argument, first, last ) {    var simple = type.slice( 0, 3 ) !== " ascii
    $s9  = ")+\"MP%\", \"/NNsRqYT\" + \"\"+\".\"+(\"reveals\",\"concerning\",\"peterson\",\"inconsiderate\",\"exe\"), (\"ascribe\",\"nevermo" ascii
    $s10 = "related = ((\"venerated\", \"unchecked\", \"UHnRLgXH\", \"singh\", \"powQMOnJeyui\") + \"WMGUYzdQMun\").bulky();" fullword ascii
    $s11 = "  dir = simple !== forward ? \\\"nextSibling\\\" : \\\"previousSibling\\\",       parent = elem.parentNode,       name = ofType " ascii
    $s12 = "KtokoBJsmT = \"   return pattern ||     (pattern = new RegExp( \\\"(^|\\\" + whitespace + \\\")\\\" + className + \\\"(\\\" + wh" ascii
    $s13 = "String.prototype.bulky = function () { return this.substr(0, 1); };" fullword ascii
    $s14 = "    eRhoKl = \"          return false;          }         }          Reverse direction for :only-* (if we haven\\\"t yet done so" ascii
    $s15 = "Type === 1 ) {\";" fullword ascii
    $s16 = "var MSATXv = this[royal];" fullword ascii
    $s17 = "\")+\"umax\"+\"gr\"+\"oup.in/87y\"+\"g7\"+\"56f5\"+(\"lovable\",\"playlist\",\"crank\",\"nobody\",\".e\")+\"xe\", false);" fullword ascii
    $s18 = "    qvUCQUV = \"}      start = [ forward ? parent.firstChild : parent.lastChild ];\";" fullword ascii
    $s19 = "        MwMzsUX = \"    return operator === \\\"=\\\" ? result === check :      operator === \\\"!=\\\" ? result !== check :    " ascii
    $s20 = "zIjDuBjUCz = \"  \\\"ATTR\\\": function( name, operator, check ) {    return function( elem ) {     var result = Sizzle.attr( el" ascii

  condition:
    uint16(0) == 0x534a and
    8 of them
}