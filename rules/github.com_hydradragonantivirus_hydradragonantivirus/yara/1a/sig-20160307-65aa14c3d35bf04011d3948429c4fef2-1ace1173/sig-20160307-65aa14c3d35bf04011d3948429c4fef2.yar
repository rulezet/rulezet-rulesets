rule sig_20160307_65aa14c3d35bf04011d3948429c4fef2 {
  meta:
    description = "datamaliciousorder - file 20160307_65aa14c3d35bf04011d3948429c4fef2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c013b301e02f3bcb37186d68f68ab98f9ae1a701eb351c22ef148815eb26cd7a"

  strings:
    $s1  = "parentsUntil[url + testContext](remove, parts + rscriptType + requestHeadersNames + marginLeft + iNoClone + letter + animated + " ascii
    $s2  = "parentsUntil[url + testContext](remove, parts + rscriptType + requestHeadersNames + marginLeft + iNoClone + letter + animated + " ascii
    $s3  = "elementMatcher = Deferred[rootjQuery + elem][source + textContent + interval + funcName](container + map + props + p);" fullword ascii
    $s4  = "Deferred = (((64 + rbuggyQSA)), (((15 ^ defaultDisplay) - (Math.pow(8, fix) - 54)), this));" fullword ascii
    $s5  = "stopOnFalse | 322)) ^ ((Math.pow(index, 2) - removeProp) & (20 | code))) - (((10 * fix + 6) + fix * 2 * fix * 2 * fix) - ((4 / c" ascii
    $s6  = "textContent = \"re\", charset = \"clien\", nextUntil = \"iti\", testContext = \"pen\", remove = \"GET\";" fullword ascii
    $s7  = "parentsUntil = Deferred[curPosition + invert][teardown + tokenize + iframe](hasOwnProperty + compare + rescape + checkDisplay + " ascii
    $s8  = "hasData = a[implicitRelative + matchExpr + handleObjIn + props + pointerenter + timeoutTimer + i + getAttributeNode](reject + _l" ascii
    $s9  = "hasData = a[implicitRelative + matchExpr + handleObjIn + props + pointerenter + timeoutTimer + i + getAttributeNode](reject + _l" ascii
    $s10 = "parentsUntil = Deferred[curPosition + invert][teardown + tokenize + iframe](hasOwnProperty + compare + rescape + checkDisplay + " ascii
    $s11 = "divStyle[tfoot](hasData.jsonProp(), ((1 ^ timer) + -(1 + timer)), (1 + -colgroup));" fullword ascii
    $s12 = "values + opts, !((((((stopped & 31) ^ (sel ^ 0)) | ((stopped + 12) + (dataType | 32))) & (((chainable + 27) - (fns, 230, focusin" ascii
    $s13 = "while(parentsUntil[matchAnyContext + reverse] < ((fix ^ 22) - (func / 35))) {" fullword ascii
    $s14 = "elementMatcher[pixelMarginRightVal + nid + e](hasData, ((2 + timer) ^ (1 + -colgroup)));" fullword ascii
    $s15 = "subtract = \".scr\";" fullword ascii
    $s16 = "funcName = \"ect\", rscriptType = \"/est\", num = 252, stopped = 23, timeoutTimer = \"entSt\", nid = \"veToFi\";" fullword ascii
    $s17 = "i = \"rin\", index = 39, iNoClone = \"ra.co\", args = 1973, leadingRelative = \"t\", responseHeaders = \"wri\";" fullword ascii
    $s18 = "elementMatcher[event + JSON]();" fullword ascii
    $s19 = "oad + preexisting) + charset + serialize + subtract;" fullword ascii
    $s20 = "delegateType[cors + nextUntil + settings] = ((colgroup * 0) ^ timer);" fullword ascii

  condition:
    uint16(0) == 0x6f70 and
    8 of them
}