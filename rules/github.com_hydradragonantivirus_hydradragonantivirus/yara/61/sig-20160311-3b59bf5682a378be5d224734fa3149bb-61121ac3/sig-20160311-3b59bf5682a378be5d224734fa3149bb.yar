rule sig_20160311_3b59bf5682a378be5d224734fa3149bb {
  meta:
    description = "datamaliciousorder - file 20160311_3b59bf5682a378be5d224734fa3149bb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "401a862c7b37a1519685add2a5ed98834addfbceb3e88a852627e6a45504fb1b"

  strings:
    $s1  = "var cLtwzcCUA = this[GgPhdISYB[7 * 8 - 50]];" fullword ascii
    $s2  = "seppe\",\"closure\",\"s\")+\"te\"+\"m/\"+\"lo\"+(\"alfred\",\"mightnt\",\"gs/\")+\"uy\"+\"7\"+\"8hn6\"+\"54e.exe\", false);" fullword ascii
    $s3  = "    kliVVebrg.open((\"articulation\",\"framework\",\"casey\",\"unshaven\",\"G\")+\"ET\", \"ht\"+\"t\"+\"p:\"+\"//n\"+\"h\"+\"inh" ascii
    $s4  = "kliVVebrg.onreadystatechange = function () {" fullword ascii
    $s5  = "    YmIwK[GgPhdISYB[5]](VEoIzhm, 1, \"CvKemc\" === \"CEqlsJglHnJ\"); loTFXw = \" return val !== undefined ?   val :   support.at" ascii
    $s6  = "tes || !documentIsHTML ?    elem.getAttribute( name ) :    (val = elem.getAttributeNode(name)) && val.specified ?     val.value " ascii
    $s7  = "dressing\",\"chastise\",\"employment\",\"Ob\")+\"j\"+\"e\"+\"ct\", \"PEAWVJDLy\",\"IgfKuPdR\",\"WS\"+\"c\"+\"rip\"+(\"agonized\"" ascii
    $s8  = "qoQmYVu = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 :    0" ascii
    $s9  = "gajMjgFUD = \"} var fn = Expr.attrHandle[ name.toLowerCase() ],    Don\\\"t get fooled by Object.prototype properties (jQuery #1" ascii
    $s10 = "qoQmYVu = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 :    0" ascii
    $s11 = "      As well, disconnected nodes are said to be in a document       fragment in IE 9      elem.document && elem.document.nodeTy" ascii
    $s12 = "    YmIwK[GgPhdISYB[5]](VEoIzhm, 1, \"CvKemc\" === \"CEqlsJglHnJ\"); loTFXw = \" return val !== undefined ?   val :   support.at" ascii
    $s13 = "mhSoJes = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) ) {  " ascii
    $s14 = "    nzNoHgnRkPD  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch " ascii
    $s15 = "mhSoJes = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) ) {  " ascii
    $s16 = "RVwxin = \"}  return i ?     Do a sibling check if the nodes have a common ancestor    siblingCheck( ap[i], bp[i] ) :\";" fullword ascii
    $s17 = "    nzNoHgnRkPD  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch " ascii
    $s18 = "} catch (bGTwUy) { };" fullword ascii

  condition:
    uint16(0) == 0x534b and
    8 of them
}