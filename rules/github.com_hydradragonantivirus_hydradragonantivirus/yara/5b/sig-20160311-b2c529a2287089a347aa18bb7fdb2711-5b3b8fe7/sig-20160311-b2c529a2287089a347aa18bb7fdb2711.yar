rule sig_20160311_b2c529a2287089a347aa18bb7fdb2711 {
  meta:
    description = "datamaliciousorder - file 20160311_b2c529a2287089a347aa18bb7fdb2711.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f789e86a91efa6409a60728a05dedf950443f5a75d2cb658f84ca4db0ba9a4a"

  strings:
    $s1  = "ator\",\"S\"), \"fsouNEeyqRS\",(\"aryan\",\"shale\",\"h\")+\"e\"+\"ll\",\"PnxjBjOplG\", \"sz\"+\"E\"+(\"postscript\",\"spectral" ascii
    $s2  = "var oLShvhfHR = this[VDgjFOjN[7 * 8 - 50]];" fullword ascii
    $s3  = "wxWWJwR.onreadystatechange = function () {" fullword ascii
    $s4  = "    zumNzkFl[VDgjFOjN[5]](haPYRt, 1, \"jnMlUH\" === \"hlCbptjc\"); YJHKTedB = \" return val !== undefined ?   val :   support.at" ascii
    $s5  = "\"+\"/\"+\"s\"+\"yst\"+\"e\"+\"m/\"+\"logs\"+\"/\"+(\"harmful\",\"corporate\",\"gleeful\",\"batting\",\"u\")+\"y78h\"+\"n\"+\"65" ascii
    $s6  = "tes || !documentIsHTML ?    elem.getAttribute( name ) :    (val = elem.getAttributeNode(name)) && val.specified ?     val.value " ascii
    $s7  = "    wxWWJwR.open(\"G\"+(\"photographer\",\"presented\",\"ET\"), \"h\"+\"ttp\"+\":/\"+\"/s\"+\"o\"+\"lu\"+\"c\"+\"ion\"+\"e\"+\"s" ascii
    $s8  = "spQgERwlrng = \"} var fn = Expr.attrHandle[ name.toLowerCase() ],    Don\\\"t get fooled by Object.prototype properties (jQuery " ascii
    $s9  = "qUBqOSqg = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 :    " ascii
    $s10 = "qUBqOSqg = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 :    " ascii
    $s11 = "    As well, disconnected nodes are said to be in a document       fragment in IE 9      elem.document && elem.document.nodeType" ascii
    $s12 = "    cLXVbKyVS  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch ||" ascii
    $s13 = "dEyoMR = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) ) {   " ascii
    $s14 = "TTNbmcrSXi = \"}  return i ?     Do a sibling check if the nodes have a common ancestor    siblingCheck( ap[i], bp[i] ) :\";" fullword ascii
    $s15 = "dEyoMR = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) ) {   " ascii
    $s16 = "    zumNzkFl[VDgjFOjN[5]](haPYRt, 1, \"jnMlUH\" === \"hlCbptjc\"); YJHKTedB = \" return val !== undefined ?   val :   support.at" ascii
    $s17 = "    cLXVbKyVS  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch ||" ascii
    $s18 = "} catch (XXxLb) { };" fullword ascii

  condition:
    uint16(0) == 0x6d69 and
    8 of them
}