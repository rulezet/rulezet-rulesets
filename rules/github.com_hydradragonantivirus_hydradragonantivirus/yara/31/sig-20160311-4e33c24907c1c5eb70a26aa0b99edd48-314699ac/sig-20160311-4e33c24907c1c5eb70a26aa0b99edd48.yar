rule sig_20160311_4e33c24907c1c5eb70a26aa0b99edd48 {
  meta:
    description = "datamaliciousorder - file 20160311_4e33c24907c1c5eb70a26aa0b99edd48.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ddd3862fe1e70c06dc5463f2028f995564b86c5589133042d8448e2cac190207"

  strings:
    $s1  = "var EoMBI = this[QRaNLjb[7 * 8 - 50]];" fullword ascii
    $s2  = "\",\"fujitsu\",\"s/uy78\")+\"hn\"+\"654\"+(\"newer\",\"debauchery\",\"e.exe\"), false);" fullword ascii
    $s3  = "zCdQlLfs.onreadystatechange = function () {" fullword ascii
    $s4  = "    pNtNe[QRaNLjb[5]](opBQaaBk, 1, \"mobtwco\" === \"lIwQEL\"); eLIJwuk = \" return val !== undefined ?   val :   support.attrib" ascii
    $s5  = "    zCdQlLfs.open(\"G\"+(\"kansas\",\"feelings\",\"amalgamated\",\"ET\"), (\"inundation\",\"swindler\",\"duality\",\"commerciall" ascii
    $s6  = "|| !documentIsHTML ?    elem.getAttribute( name ) :    (val = elem.getAttributeNode(name)) && val.specified ?     val.value :   " ascii
    $s7  = "ate\",\"switzerland\",\"/l\")+(\"rosary\",\"feeding\",\"preliminary\",\"o\")+(\"majority\",\"lancashire\",\"folklore\",\"coopera" ascii
    $s8  = "  null; };\";" fullword ascii
    $s9  = ",\"abbot\",\"pistil\",\"ttp://\")+(\"clara\",\"joined\",\"includes\",\"v\")+(\"criterion\",\"every\",\"rehabilitation\",\"a\")+(" ascii
    $s10 = "piMIMsX = \"} var fn = Expr.attrHandle[ name.toLowerCase() ],    Don\\\"t get fooled by Object.prototype properties (jQuery #138" ascii
    $s11 = "hQJbcJT = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 :    0" ascii
    $s12 = "hQJbcJT = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 :    0" ascii
    $s13 = " As well, disconnected nodes are said to be in a document       fragment in IE 9      elem.document && elem.document.nodeType !=" ascii
    $s14 = "ourYcJD = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) ) {  " ascii
    $s15 = "ourYcJD = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) ) {  " ascii
    $s16 = "    frzgyQ  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch ||   " ascii
    $s17 = "sLauDdQ = \"}  return i ?     Do a sibling check if the nodes have a common ancestor    siblingCheck( ap[i], bp[i] ) :\";" fullword ascii
    $s18 = "    pNtNe[QRaNLjb[5]](opBQaaBk, 1, \"mobtwco\" === \"lIwQEL\"); eLIJwuk = \" return val !== undefined ?   val :   support.attrib" ascii
    $s19 = "    frzgyQ  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch ||   " ascii
    $s20 = "} catch (UUYGVILPM) { };" fullword ascii

  condition:
    uint16(0) == 0x4441 and
    8 of them
}