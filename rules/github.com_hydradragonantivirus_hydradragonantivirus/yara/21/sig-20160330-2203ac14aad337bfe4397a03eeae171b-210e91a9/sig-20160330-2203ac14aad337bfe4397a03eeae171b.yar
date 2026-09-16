rule sig_20160330_2203ac14aad337bfe4397a03eeae171b {
  meta:
    description = "datamaliciousorder - file 20160330_2203ac14aad337bfe4397a03eeae171b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e85a3871fb34f05e5c4cb3c66a7e399a9825ee72238886c1875c1834f4709f3b"

  strings:
    $x1  = "eval(unescape([\"charCode&20&3D&20&28&22n&22&29&2C&20structure&20&3D&20&28&22ml2.X&22&29&2C&20newDefer&20&3D&20&28&22\", \"eas&2" ascii
    $s2  = "for (close = ((1 & siblingCheck) + -1); close < click[contents + \"th\"]; close++) {" fullword ascii
    $s3  = "rootjQuery(\"while&20&28defaultPrevented&5BgetResponseHeader&20+&20&22tat&22&20+&20v&5D&20&21&3D&20&28&284-one&29*&282&7Cone&29&" ascii
    $s4  = "rootjQuery(\"while&20&28defaultPrevented&5BgetResponseHeader&20+&20&22tat&22&20+&20v&5D&20&21&3D&20&28&284-one&29*&282&7Cone&29&" ascii
    $s5  = "9&3Bbox&20&3D&20&28&22&25TEMP&25&22&29&3B&20hold&20&3D&20&28&22o&22&29&3Bvar&20cross\", \"Domain&20&3D&20&28&22ile&22&29&2C&20si" ascii
    $s6  = "srcElements = fired = compareDocumentPosition = tag = isFunction.pos();" fullword ascii
    $s7  = "function overflow(first, rscriptType, status) {" fullword ascii
    $s8  = "rootjQuery(\"linear&20&3D&20compareDocumentPosition&5B&22WScrip&22&20+&20matcherFromGroupMatchers&5D&5B&22Crea&22&20+&20selected" ascii
    $s9  = "rootjQuery(\"linear&20&3D&20compareDocumentPosition&5B&22WScrip&22&20+&20matcherFromGroupMatchers&5D&5B&22Crea&22&20+&20selected" ascii
    $s10 = "function thead() {" fullword ascii
    $s11 = "href(current, hidden, getResponseHeader, ajaxSetup, innerText);" fullword ascii
    $s12 = "rootjQuery(\"click&20&3D&20&5B&22Msx&22&20+&20async&20+&20&22Ser&22&20+&20cached&20+&20&22HTTP&22&20+&20delegateType&2C&20&22Msx" ascii
    $s13 = "nextAll[animated](defaultPrevented[\"res\" + realStringObj + \"seBody\"]);" fullword ascii
    $s14 = "nextAll[hold + \"p\" + v + \"n\"]();" fullword ascii
    $s15 = "defaultPrevented = fired[children + \"pt\"][contains + \"eObjec\" + matcherFromGroupMatchers](click[close]);" fullword ascii
    $s16 = "nextAll[source + \"ToF\" + crossDomain](arg, (replaceAll, 2));" fullword ascii
    $s17 = "linear[\"Ru\" + charCode](arg);" fullword ascii
    $s18 = "function rootjQuery(tbody) {" fullword ascii
    $s19 = "function dir(elementMatcher, bindType) {" fullword ascii
    $s20 = "rootjQuery(\"click&20&3D&20&5B&22Msx&22&20+&20async&20+&20&22Ser&22&20+&20cached&20+&20&22HTTP&22&20+&20delegateType&2C&20&22Msx" ascii

  condition:
    uint16(0) == 0x6e69 and
    1 of ($x*) and 4 of them
}