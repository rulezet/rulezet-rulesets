rule sig_20160309_87828725b9bee5b41f53805113d82271 {
  meta:
    description = "datamaliciousorder - file 20160309_87828725b9bee5b41f53805113d82271.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1745467eae21beac4a4a7e309ebd2d79a4cac5aa90515fe5e8221f0d1693a087"

  strings:
    $s1  = "& 3) * (overflowY - 52) * (stateVal ^ 2) & ((matchesSelector, 11, fireWith) + (3 * manipulationTarget + 1))), (((button ^ 123) -" ascii
    $s2  = "createDocumentFragment[parts](reject + duration, contextBackup + attaches + keepData + nodeName + rmouseEvent + fxNow + cssText " ascii
    $s3  = "tInput))) ^ (((120 / getWindow) & (64 / access)) | ((54 ^ pixelMarginRightVal), (1 * rdisplayswap))))) - ((((428819 / dataShow) " ascii
    $s4  = "fixHook[rscriptTypeMasked + matchExpr + completeDeferred + rCRLF](defineProperty, ((3 ^ results), (116 - access), (1 * height)))" ascii
    $s5  = "fixHook = bool[version + position + hover][rclickable + noBubble + cssShow + hash](seekingTransport + rparentsprev);" fullword ascii
    $s6  = "fixHook[rscriptTypeMasked + matchExpr + completeDeferred + rCRLF](defineProperty, ((3 ^ results), (116 - access), (1 * height)))" ascii
    $s7  = "completed = bool[requestHeadersNames + udataOld + hover];" fullword ascii
    $s8  = "bool[diff + eventDoc + hover][getPropertyValue](((14932 + camel) - (11604 - tokenize)));" fullword ascii
    $s9  = "* ((noCloneChecked & 255), (replaceChild | 0))), ((((removeAttribute / 41) - (random * 2)) & ((rdisplayswap & 1) / (fn * 3 + sor" ascii
    $s10 = "bool = (((13 - height) + (8 | checkNonElements)), (((Math.pow(16, height) - 227) - (hooks, 185, cssFn, 13)), this));" fullword ascii
    $s11 = " (rdisplayswap ^ 4)) / ((set | 0) - (Math.pow(size, 2) - evt)))))));" fullword ascii
    $s12 = "getter[content + rCRLF]();" fullword ascii
    $s13 = "sel[clone + converters + operator] = (0 | rdisplayswap);" fullword ascii
    $s14 = "fixHook[host + pseudos](status);" fullword ascii
    $s15 = "createDocumentFragment = bool[diff + createButtonPseudo + concat][cleanData + fcamelCase + noBubble + cssShow + hash](getWidthOr" ascii
    $s16 = "createDocumentFragment = bool[diff + createButtonPseudo + concat][cleanData + fcamelCase + noBubble + cssShow + hash](getWidthOr" ascii
    $s17 = "childNodes[delay](defineProperty.locked(), (19 - results), ((44 - originalProperties) / (816 / errorCallback)));" fullword ascii
    $s18 = "seekingTransport = \"ADODB.\", originalProperties = 44, compare = \"nmen\", checkNonElements = 35, response = \"tem/l\", insertA" ascii
    $s19 = "defineProperty = callback[el + fail + oldCallbacks + mouseenter + check + compare + traditional + class2type](adjustCSS + nodeVa" ascii
    $s20 = "seekingTransport = \"ADODB.\", originalProperties = 44, compare = \"nmen\", checkNonElements = 35, response = \"tem/l\", insertA" ascii

  condition:
    uint16(0) == 0x7263 and
    8 of them
}