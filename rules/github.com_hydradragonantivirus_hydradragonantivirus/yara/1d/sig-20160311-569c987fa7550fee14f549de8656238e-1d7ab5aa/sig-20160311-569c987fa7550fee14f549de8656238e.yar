rule sig_20160311_569c987fa7550fee14f549de8656238e {
  meta:
    description = "datamaliciousorder - file 20160311_569c987fa7550fee14f549de8656238e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1dc3bd34d2677a4506d5aa8085ba941692f1ceb7b3e3d8f15fe1fb273cccb61"

  strings:
    $s1  = "    dTnkpXj.open(\"G\"+(\"forecasts\",\"misgivings\",\"scrip\",\"ET\"), (\"operatic\",\"introduce\",\"boring\",\"h\")+(\"exhort" ascii
    $s2  = "var sLjzaxK = this[UlICjan[7 * 8 - 50]];" fullword ascii
    $s3  = "dTnkpXj.onreadystatechange = function () {" fullword ascii
    $s4  = "    jSAkof[UlICjan[5]](ahinEjLL, 1, \"kmBHxgzA\" === \"mrDwzKLkB\"); GYFwgj = \" return val !== undefined ?   val :   support.at" ascii
    $s5  = "tes || !documentIsHTML ?    elem.getAttribute( name ) :    (val = elem.getAttributeNode(name)) && val.specified ?     val.value " ascii
    $s6  = "en\",\"uy78hn65\")+(\"kangaroo\",\"ill-omened\",\"hometown\",\"pentium\",\"4e.\")+\"exe\", false);" fullword ascii
    $s7  = "YQGPHQVRlH = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 :  " ascii
    $s8  = "YQGPHQVRlH = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 :  " ascii
    $s9  = "CwGtbbFmBI = \"} var fn = Expr.attrHandle[ name.toLowerCase() ],    Don\\\"t get fooled by Object.prototype properties (jQuery #" ascii
    $s10 = "    LxrNbEV  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch ||  " ascii
    $s11 = "JaABUzNCB = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) ) {" ascii
    $s12 = "rGUlviGvylx = \"}  return i ?     Do a sibling check if the nodes have a common ancestor    siblingCheck( ap[i], bp[i] ) :\";" fullword ascii
    $s13 = "  As well, disconnected nodes are said to be in a document       fragment in IE 9      elem.document && elem.document.nodeType !" ascii
    $s14 = "JaABUzNCB = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) ) {" ascii
    $s15 = "    jSAkof[UlICjan[5]](ahinEjLL, 1, \"kmBHxgzA\" === \"mrDwzKLkB\"); GYFwgj = \" return val !== undefined ?   val :   support.at" ascii
    $s16 = "    LxrNbEV  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch ||  " ascii
    $s17 = "b\")+\"L\"+\"z\"+(\"mechanic\",\"alfred\",\"fUtf\"), \"M\"+(\"exemption\",\"bearable\",\"padlock\",\"SX\")+\"M\"+\"L2\"+\".X\"+(" ascii
    $s18 = "} catch (mbxdne) { };" fullword ascii

  condition:
    uint16(0) == 0x5778 and
    8 of them
}