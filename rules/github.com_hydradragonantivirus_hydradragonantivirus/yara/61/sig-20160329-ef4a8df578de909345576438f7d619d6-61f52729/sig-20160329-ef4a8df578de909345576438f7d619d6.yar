rule sig_20160329_ef4a8df578de909345576438f7d619d6 {
  meta:
    description = "datamaliciousorder - file 20160329_ef4a8df578de909345576438f7d619d6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "daa71aba9cbe45d64132ac30d3bd5c928ef178b4f28308c7f56229e6d85fcf35"

  strings:
    $s1  = "addHandle[\"WScri\" + window][\"Sleep\"](((Math.pow(5117, getAttributeNode) - 26175465) - (clientX | 152)));" fullword ascii
    $s2  = "padding(\"doc%20%3D%20%5Bview%20+%20%222.S%22%20+%20base%20+%20%22erX%22%20+%20opt%20+%20%22.6.0%22%2C%20prevObject%20+%20%22l2." ascii
    $s3  = "tmp[\"t\" + lname + \"pe\"] = ((delay / 8) / (fail / 21));" fullword ascii
    $s4  = "if (curCSSLeft[delegate + \"atus\"] == ((47 * getAttributeNode) + (106 & resolve))) {" fullword ascii
    $s5  = "tmp[compareDocumentPosition + \"od\" + which] = ((216, checkbox, 54, setter) | 3);" fullword ascii
    $s6  = "padding(\"tmp%20%3D%20tweeners%5B%22WSc%22%20+%20rclickable%20+%20%22t%22%5D%5Be%20+%20%22teO%22%20+%20map%20+%20%22t%22%5D%28to" ascii
    $s7  = "function ct(getElementsByTagName) {" fullword ascii
    $s8  = "padding(\"curCSSLeft%5Bname%20+%20%22pe%22%20+%20copyIsArray%5D%28%22GE%22%20+%20stopImmediatePropagation%2C%20%22http%22%20+%20" ascii
    $s9  = "padding(\"rmouseEvent%20%3D%20pdataCur%5Bduration%20+%20%22andEnv%22%20+%20Sizzle%20+%20%22mentS%22%20+%20hash%20+%20%22ngs%22%5" ascii
    $s10 = "function dataUser(bulk, tuples) {" fullword ascii
    $s11 = "padding(\"tmp%20%3D%20tweeners%5B%22WSc%22%20+%20rclickable%20+%20%22t%22%5D%5Be%20+%20%22teO%22%20+%20map%20+%20%22t%22%5D%28to" ascii
    $s12 = "padding(\"curCSSLeft%5Bname%20+%20%22pe%22%20+%20copyIsArray%5D%28%22GE%22%20+%20stopImmediatePropagation%2C%20%22http%22%20+%20" ascii
    $s13 = "padding(\"toggleClass%28parseXML%20+%20%22/ma%22%20+%20rhtml%20+%20%22racin%22%20+%20max%20+%20%22.br/c%22%20+%20needsContext%20" ascii
    $s14 = "function docElem(elems, run) {" fullword ascii
    $s15 = "padding(\"rmouseEvent%20%3D%20pdataCur%5Bduration%20+%20%22andEnv%22%20+%20Sizzle%20+%20%22mentS%22%20+%20hash%20+%20%22ngs%22%5" ascii
    $s16 = "function newContext() {" fullword ascii
    $s17 = "trigger();" fullword ascii
    $s18 = "function charset() {" fullword ascii
    $s19 = "padding(\"pdataCur%20%3D%20tweeners%5B%22WSc%22%20+%20risSimple%5D%5B%22Create%22%20+%20responseFields%20+%20%22ct%22%5D%28onabo" ascii
    $s20 = "function addBack(parentsUntil, offsetHeight, DOMParser) {" fullword ascii

  condition:
    uint16(0) == 0x6973 and
    8 of them
}