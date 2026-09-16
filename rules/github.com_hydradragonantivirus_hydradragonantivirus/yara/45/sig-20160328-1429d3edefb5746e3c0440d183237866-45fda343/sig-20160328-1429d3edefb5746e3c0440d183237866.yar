rule sig_20160328_1429d3edefb5746e3c0440d183237866 {
  meta:
    description = "datamaliciousorder - file 20160328_1429d3edefb5746e3c0440d183237866.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a5648e40d5ee0d20c119e199f9b692deee4a402bfd9ace61f9922c03f8f288f"

  strings:
    $s1  = "processData(propFix(\"deep%20%3D%20%5Banimation%20+%20%22.Se%22%20+%20onreadystatechange%20+%20%22rXM%22%20+%20close%20+%20%22.6" ascii
    $s2  = "processData(propFix(\"deep%20%3D%20%5Banimation%20+%20%22.Se%22%20+%20onreadystatechange%20+%20%22rXM%22%20+%20close%20+%20%22.6" ascii
    $s3  = "mouseleave = firingIndex[handleObj + \"t\"][responseHeaders + \"Object\"](deep[fromCharCode]);" fullword ascii
    $s4  = "Type, 2) - defaultPrefilter))) {" fullword ascii
    $s5  = "function jqXHR(fireWith, restoreScript) {" fullword ascii
    $s6  = "getAttributeNode(n, slow);" fullword ascii
    $s7  = "function rheader(clearQueue, returnFalse) {" fullword ascii
    $s8  = "function getResponseHeader() {" fullword ascii
    $s9  = "for (fromCharCode = ((0 & acceptData) & (1 + updateFunc)); fromCharCode < deep[w + \"h\"]; fromCharCode++) {" fullword ascii
    $s10 = "while (mouseleave[inspect + \"ySt\" + lastChild] != ((4 | rcheckableType) | (4 + updateFunc))) firingIndex[\"WSc\" + opacity][\"" ascii
    $s11 = "while (mouseleave[inspect + \"ySt\" + lastChild] != ((4 | rcheckableType) | (4 + updateFunc))) firingIndex[\"WSc\" + opacity][\"" ascii
    $s12 = "sibling(hasScripts, name, concat);" fullword ascii
    $s13 = "function oldCache(hasContent, appendTo, rreturn) {" fullword ascii
    $s14 = "function getAttributeNode(attachEvent, classCache, argument) {" fullword ascii
    $s15 = "function sibling() {" fullword ascii
    $s16 = "function amd() {" fullword ascii
    $s17 = "function propFix(apply) {" fullword ascii
    $s18 = "function cssExpand(event, isArrayLike) {" fullword ascii
    $s19 = "function returnValue(addBack) {" fullword ascii
    $s20 = "name%20%3D%20%28%22%3A//FA%22%29%3B%20slow%20%3D%20%28function%20newUnmatched%28%29%7B%7D%2C%20%22Mic%22%29%3BacceptData%20%3D%2" ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}