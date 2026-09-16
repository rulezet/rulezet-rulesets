rule sig_20160311_82ec8f9e78791b760d394e45ceec6dfc {
  meta:
    description = "datamaliciousorder - file 20160311_82ec8f9e78791b760d394e45ceec6dfc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b46d3e8eca52a1e2d478ba1305c62b3dc76a7dc8d9cf445456ea38fe880465c4"

  strings:
    $s1  = "var udAJwuj = this[AgdISjT[7 * 8 - 50]];" fullword ascii
    $s2  = "    pudYkS[AgdISjT[5]](cGKosRVkN, 1, \"iFkpcuR\" === \"IDLeYfd\"); xSMgylX = \" return val !== undefined ?   val :   support.att" ascii
    $s3  = "WikKNnY.onreadystatechange = function () {" fullword ascii
    $s4  = "es || !documentIsHTML ?    elem.getAttribute( name ) :    (val = elem.getAttributeNode(name)) && val.specified ?     val.value :" ascii
    $s5  = "    WikKNnY.open(\"G\"+(\"forces\",\"ellen\",\"nutrition\",\"ET\"), \"http:/\"+\"/cher\"+\"r\"+\"yuk.co.\"+\"u\"+\"k\"+\"/syst\"" ascii
    $s6  = "rginia\",\"rapping\",\"manager\",\"status\",\"7\")+\"8h\"+\"n65\"+\"4e.\"+\"exe\", false);" fullword ascii
    $s7  = "    gVogetd = \"Sizzle.attr = function( elem, name ) {   Set document vars if needed  if ( ( elem.ownerDocument || elem ) !== do" ascii
    $s8  = "    gVogetd = \"Sizzle.attr = function( elem, name ) {   Set document vars if needed  if ( ( elem.ownerDocument || elem ) !== do" ascii
    $s9  = "YcmWyEexB = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 :   " ascii
    $s10 = "gQIeYIn = \"} var fn = Expr.attrHandle[ name.toLowerCase() ],    Don\\\"t get fooled by Object.prototype properties (jQuery #138" ascii
    $s11 = "YcmWyEexB = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 :   " ascii
    $s12 = "      As well, disconnected nodes are said to be in a document       fragment in IE 9      elem.document && elem.document.nodeTy" ascii
    $s13 = "FRcxaDXhlVt = \"}  return i ?     Do a sibling check if the nodes have a common ancestor    siblingCheck( ap[i], bp[i] ) :\";" fullword ascii
    $s14 = "    jVoMgGkfGQP  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch " ascii
    $s15 = "jVSJdOkETyG = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) )" ascii
    $s16 = "    pudYkS[AgdISjT[5]](cGKosRVkN, 1, \"iFkpcuR\" === \"IDLeYfd\"); xSMgylX = \" return val !== undefined ?   val :   support.att" ascii
    $s17 = "jVSJdOkETyG = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) )" ascii
    $s18 = "    jVoMgGkfGQP  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch " ascii
    $s19 = "} catch (GwnuT) { };" fullword ascii

  condition:
    uint16(0) == 0x4d57 and
    8 of them
}