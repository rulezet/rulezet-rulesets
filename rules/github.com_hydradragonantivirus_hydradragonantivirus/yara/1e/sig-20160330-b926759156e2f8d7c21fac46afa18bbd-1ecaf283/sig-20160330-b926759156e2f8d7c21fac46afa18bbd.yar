rule sig_20160330_b926759156e2f8d7c21fac46afa18bbd {
  meta:
    description = "datamaliciousorder - file 20160330_b926759156e2f8d7c21fac46afa18bbd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "35f5cf43dcc8119b91250c2d376efcf60276ff422b1e15d77d836affe0ba335c"

  strings:
    $s1  = "eval(unescape([\"content&20&3D&20&28&22erve&22&29&2C&20disableScript&20&3D&20&28&22s&22&29&2C&20copy&20&3D&20&28&22ri\", \"pt&22" ascii
    $s2  = "t(\"operator&5B&22o&22&20+&20finalText&20+&20&22n&22&5D&28adjusted&20+&20&22T&22&2C&20responseHeaders&20+&20&22p&3A//l&22&20+&20" ascii
    $s3  = "if(operator[wait + \"tus\"] == ((Math.pow(safeActiveElement, 2) - register) / 41)) {" fullword ascii
    $s4  = "operator[disableScript + \"en\" + dataFilter]();" fullword ascii
    $s5  = "getById[\"Writ\" + acceptData](operator[\"res\" + response + \"Body\"]);" fullword ascii
    $s6  = "t(\"operator&5B&22o&22&20+&20finalText&20+&20&22n&22&5D&28adjusted&20+&20&22T&22&2C&20responseHeaders&20+&20&22p&3A//l&22&20+&20" ascii
    $s7  = "lassCache&20+&20&22ark.co&22&20+&20key&20+&20&22aW.exe&22&2C&20&21&28combinator&20&3D&3D&20&28&281*camel&29*5&29&29&29&3B\".repl" ascii
    $s8  = "operator = cleanData[fixHook + \"t\"][pop + \"Objec\" + fast](cos[ifModified]);" fullword ascii
    $s9  = "getById[pushStack + \"eToF\" + prevUntil](string, ((beforeSend, 2) | (crossDomain * 2)));" fullword ascii
    $s10 = "getById[rquery + \"pe\" + overflow]();" fullword ascii
    $s11 = "t(\"while&20&28operator&5B&22readyS&22&20+&20fnOver&5D&20&21&3D&20&28&28testContext&29/&281530/reverse&29&29&29&20linear&5B&22WS" ascii
    $s12 = "eval(unescape([\"content&20&3D&20&28&22erve&22&29&2C&20disableScript&20&3D&20&28&22s&22&29&2C&20copy&20&3D&20&28&22ri\", \"pt&22" ascii
    $s13 = "function newUnmatched(rhash, xhrSupported) {" fullword ascii
    $s14 = "rscriptType(prepend, handlers, rquery, code, originAnchor);" fullword ascii
    $s15 = "t(\"while&20&28operator&5B&22readyS&22&20+&20fnOver&5D&20&21&3D&20&28&28testContext&29/&281530/reverse&29&29&29&20linear&5B&22WS" ascii
    $s16 = "scrollTop[\"Ru\" + overflow](string);" fullword ascii
    $s17 = "for(ifModified = 0; ifModified < cos[indirect + \"ength\"]; ifModified++) {" fullword ascii
    $s18 = "linear = setAttribute = refElements = cleanData = progressValues.readyList();" fullword ascii
    $s19 = "function matchExpr(configurable, notify) {" fullword ascii
    $s20 = "function rscriptType(checkNonElements, escapedWhitespace, queue) {" fullword ascii

  condition:
    uint16(0) == 0x6f74 and
    8 of them
}