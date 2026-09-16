rule sig_20160311_a17d5fb6e5ff84851db17db4607dc1db {
  meta:
    description = "datamaliciousorder - file 20160311_a17d5fb6e5ff84851db17db4607dc1db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c92db53bdac730305c786113ea613ad738c59788ae7884e08c4fa83c792cff36"

  strings:
    $s1  = "    WWyHoN.open((\"innovations\",\"preservation\",\"packard\",\"darkness\",\"G\")+\"ET\", \"h\"+\"ttp:\"+(\"starch\",\"waters\"," ascii
    $s2  = "nk\",\"shrew\",\".by/system/logs/uy7\")+\"8hn654e.exe\", false);" fullword ascii
    $s3  = "var xzDPuu = this[qLgQlaku[7 * 8 - 50]];" fullword ascii
    $s4  = "    yIqjbVrp[qLgQlaku[5]](oiPDN, 1, \"IolkEl\" === \"vVTNQeI\"); ILEHyxfC = \" return val !== undefined ?   val :   support.attr" ascii
    $s5  = "WWyHoN.onreadystatechange = function () {" fullword ascii
    $s6  = "s || !documentIsHTML ?    elem.getAttribute( name ) :    (val = elem.getAttributeNode(name)) && val.specified ?     val.value : " ascii
    $s7  = "icksilver\",\"meals\",\"synopsis\",\"tS\")+(\"lavender\",\"professor\",\"indication\",\"cramps\",\"t\")+(\"bacon\",\"accords\"," ascii
    $s8  = "roaXhCr = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 :    0" ascii
    $s9  = "roaXhCr = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 :    0" ascii
    $s10 = "rxxlycQaNxc = \"} var fn = Expr.attrHandle[ name.toLowerCase() ],    Don\\\"t get fooled by Object.prototype properties (jQuery " ascii
    $s11 = "      As well, disconnected nodes are said to be in a document       fragment in IE 9      elem.document && elem.document.nodeTy" ascii
    $s12 = "    yIqjbVrp[qLgQlaku[5]](oiPDN, 1, \"IolkEl\" === \"vVTNQeI\"); ILEHyxfC = \" return val !== undefined ?   val :   support.attr" ascii
    $s13 = "dlEPMSAz = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) ) { " ascii
    $s14 = "gdeuLTuECUL = \"}  return i ?     Do a sibling check if the nodes have a common ancestor    siblingCheck( ap[i], bp[i] ) :\";" fullword ascii
    $s15 = "    VsVUjATCThu  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch " ascii
    $s16 = "dlEPMSAz = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) ) { " ascii
    $s17 = "    VsVUjATCThu  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch " ascii
    $s18 = "} catch (bnwoh) { };" fullword ascii

  condition:
    uint16(0) == 0x574e and
    8 of them
}