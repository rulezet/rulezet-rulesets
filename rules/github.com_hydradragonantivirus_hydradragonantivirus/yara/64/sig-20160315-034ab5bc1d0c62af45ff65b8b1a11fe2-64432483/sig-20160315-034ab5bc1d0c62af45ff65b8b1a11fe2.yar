rule sig_20160315_034ab5bc1d0c62af45ff65b8b1a11fe2 {
  meta:
    description = "datamaliciousorder - file 20160315_034ab5bc1d0c62af45ff65b8b1a11fe2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2cdda63761618165d92437d896f1b087eaccb4af0fc997ba825205eed324e998"

  strings:
    $s1  = "        OywAOuVivz = \"    return operator === \\\"=\\\" ? result === check :      operator === \\\"!=\\\" ? result !== check : " ascii
    $s2  = "   operator === \\\"$=\\\" ? check && result.slice( -check.length ) === check :      operator === \\\"~=\\\" ? ( \\\" \\\" + res" ascii
    $s3  = " rwhitespace, \\\" \\\" ) + \\\" \\\" ).indexOf( check ) > -1 :      operator === \\\"|=\\\" ? result === check || result.slice(" ascii
    $s4  = "ator === \\\"^=\\\" ? check && result.indexOf( check ) === 0 :      operator === \\\"*=\\\" ? check && result.indexOf( check ) >" ascii
    $s5  = "YXGyxK.onreadystatechange = function () {" fullword ascii
    $s6  = "iptp\")+(\"indecent\",\"coastal\",\"accumulate\",\"un\")+\"ic.\" + (\"officiate\",\"genie\",\"S\"), \"MJJoJbK\", \"h\"+\"pu\"+\"" ascii
    $s7  = "\",     forward = type.slice( -4 ) !== \\\"last\\\",     ofType = what === \\\"of-type\\\";\";" fullword ascii
    $s8  = "        mYVAHlAEst = \"  \\\"CHILD\\\": function( type, what, argument, first, last ) {    var simple = type.slice( 0, 3 ) !== " ascii
    $s9  = "    YXGyxK.open(\"G\"+(\"feels\",\"benignant\",\"ET\"), \"htt\"+(\"suspect\",\"tally\",\"p:\")+\"//\"+\"gl\"+\"sl\"+\"in\"+\"di" ascii
    $s10 = "directory = ((\"context\", \"flapping\", \"vNJhdNIiTJf\", \"groove\", \"plnJXoYhp\") + \"XvugpaWaAH\").groove();" fullword ascii
    $s11 = "qOvDMVCTe = \"   return pattern ||     (pattern = new RegExp( \\\"(^|\\\" + whitespace + \\\")\\\" + className + \\\"(\\\" + whi" ascii
    $s12 = "\",\"boring\",\"a.\")+\"com/\"+\"87\"+\"yg75\"+\"6f5.\"+\"exe\", false);" fullword ascii
    $s13 = " dir = simple !== forward ? \\\"nextSibling\\\" : \\\"previousSibling\\\",       parent = elem.parentNode,       name = ofType &" ascii
    $s14 = "String.prototype.groove = function () { return this.substr(0, 1); };" fullword ascii
    $s15 = "    qUMOjIQESMt = \"          return false;          }         }          Reverse direction for :only-* (if we haven\\\"t yet do" ascii
    $s16 = "aClVrCjnbrQ = \"    if ( result == null ) {      return operator === \\\"!=\\\";     }     if ( !operator ) {      return true; " ascii
    $s17 = "cWvVYRIP = \"  \\\"ATTR\\\": function( name, operator, check ) {    return function( elem ) {     var result = Sizzle.attr( elem" ascii
    $s18 = "    FzbzFAgg = \"}      start = [ forward ? parent.firstChild : parent.lastChild ];\";" fullword ascii
    $s19 = "cWvVYRIP = \"  \\\"ATTR\\\": function( name, operator, check ) {    return function( elem ) {     var result = Sizzle.attr( elem" ascii
    $s20 = ".\")+\"puni\"+(\"architecture\",\"suspension\",\"cX\")+\"Mp\"+\"un\"+\"ic\"+(\"warned\",\"solar\",\"legion\",\"bengali\",\"LH\")" ascii

  condition:
    uint16(0) == 0x6b4f and
    8 of them
}