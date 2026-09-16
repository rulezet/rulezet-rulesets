rule sig_20160311_98a93f64ea8ee0da0a80f279f8b331cd {
  meta:
    description = "datamaliciousorder - file 20160311_98a93f64ea8ee0da0a80f279f8b331cd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "188434352fa9378324e3a56307805147907c0f40ceeac430db42fcb8788f5483"

  strings:
    $s1  = "    bGaPXqQwI.open((\"plait\",\"agent\",\"G\")+\"ET\", \"http:\"+\"//\"+(\"bastion\",\"waves\",\"improving\",\"yander\")+\".by/s" ascii
    $s2  = "var BMHtmUFn = this[piCmYBj[7 * 8 - 50]];" fullword ascii
    $s3  = "+\"65\"+\"4e\"+\".exe\", false);" fullword ascii
    $s4  = "bGaPXqQwI.onreadystatechange = function () {" fullword ascii
    $s5  = "    lljuOS[piCmYBj[5]](Gusxz, 1, \"dmjTOC\" === \"QzWSyoyWcM\"); KasvVovV = \" return val !== undefined ?   val :   support.attr" ascii
    $s6  = "xplOgkpnLI = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 :  " ascii
    $s7  = "arena = ((\"myrtle\", \"fifty-eight\", \"BBBXXIqRdH\", \"interface\", \"pNuKxrMGJBD\") + \"aRkvONpWw\").enquiry()" fullword ascii
    $s8  = "xplOgkpnLI = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 :  " ascii
    $s9  = "s || !documentIsHTML ?    elem.getAttribute( name ) :    (val = elem.getAttributeNode(name)) && val.specified ?     val.value : " ascii
    $s10 = "String.prototype.enquiry = function () { return this.substr(0, 1); };" fullword ascii
    $s11 = "CdFkQCJ = \"} var fn = Expr.attrHandle[ name.toLowerCase() ],    Don\\\"t get fooled by Object.prototype properties (jQuery #138" ascii
    $s12 = "   As well, disconnected nodes are said to be in a document       fragment in IE 9      elem.document && elem.document.nodeType " ascii
    $s13 = "    lljuOS[piCmYBj[5]](Gusxz, 1, \"dmjTOC\" === \"QzWSyoyWcM\"); KasvVovV = \" return val !== undefined ?   val :   support.attr" ascii
    $s14 = "bTaATLrmqlO = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) )" ascii
    $s15 = "    RiANuTOP  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch || " ascii
    $s16 = "bTaATLrmqlO = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) )" ascii
    $s17 = "HUNYdbVn = \"}  return i ?     Do a sibling check if the nodes have a common ancestor    siblingCheck( ap[i], bp[i] ) :\";" fullword ascii
    $s18 = "    RiANuTOP  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch || " ascii
    $s19 = "} catch (dEewqQl) { };" fullword ascii

  condition:
    uint16(0) == 0x676f and
    8 of them
}