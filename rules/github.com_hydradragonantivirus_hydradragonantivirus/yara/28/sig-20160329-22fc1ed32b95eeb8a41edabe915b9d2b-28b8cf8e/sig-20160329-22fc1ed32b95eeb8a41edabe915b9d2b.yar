rule sig_20160329_22fc1ed32b95eeb8a41edabe915b9d2b {
  meta:
    description = "datamaliciousorder - file 20160329_22fc1ed32b95eeb8a41edabe915b9d2b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "535d9f7fec8dd9eb5ba701ba4bad77eeab5a9609be37a477b4f892ac6c0e8beb"

  strings:
    $s1  = "documentIsHTML = ready[resolveWith + \"pt\"][close + \"eObje\" + testContext](getWidthOrHeight[originAnchor]);" fullword ascii
    $s2  = "getComputedStyle[compare + \"n\"](getAllResponseHeaders);" fullword ascii
    $s3  = "if(documentIsHTML[\"status\"] == (Math.pow((stored + 79), (delegateType & 3)) - (count / 16))) {" fullword ascii
    $s4  = "list[getter + \"o\" + e] = ((3 & lock) | (66 / isDefaultPrevented));" fullword ascii
    $s5  = "list[\"Sav\" + cssExpand + \"e\"](getAllResponseHeaders, ((26 / fxNow) + (1 & nextAll)));" fullword ascii
    $s6  = "function rscriptType(l, throws) {" fullword ascii
    $s7  = "onerror(position, visible, compare, noop);" fullword ascii
    $s8  = "fontWeight(\"while%20%28documentIsHTML%5Bcopy%20+%20%22State%22%5D%20%21%3D%20%28%2813+dirruns%29/%28Math.pow%2844%2C%20delegate" ascii
    $s9  = "host = 160;" fullword ascii
    $s10 = "function access(postFilter, eventHandle, cur) {" fullword ascii
    $s11 = "list[\"W\" + optgroup](documentIsHTML[\"respo\" + view + \"ody\"]);" fullword ascii
    $s12 = "list[minWidth + \"e\" + matches]();" fullword ascii
    $s13 = "list[\"ty\" + settings + \"e\"] = 1;" fullword ascii
    $s14 = "function onerror() {" fullword ascii
    $s15 = "function removeEventListener() {" fullword ascii
    $s16 = "anim = filters = one = ready = cssText.responseText();" fullword ascii
    $s17 = "fontWeight(\"while%20%28documentIsHTML%5Bcopy%20+%20%22State%22%5D%20%21%3D%20%28%2813+dirruns%29/%28Math.pow%2844%2C%20delegate" ascii
    $s18 = "fontWeight(\"list%20%3D%20filters%5BresolveWith%20+%20%22pt%22%5D%5Bclose%20+%20%22eOb%22%20+%20escapedWhitespace%5D%28%22ADODB%" ascii
    $s19 = "function modified() {" fullword ascii
    $s20 = "function namespaces(rcheckableType, preexisting) {" fullword ascii

  condition:
    uint16(0) == 0x6f68 and
    8 of them
}