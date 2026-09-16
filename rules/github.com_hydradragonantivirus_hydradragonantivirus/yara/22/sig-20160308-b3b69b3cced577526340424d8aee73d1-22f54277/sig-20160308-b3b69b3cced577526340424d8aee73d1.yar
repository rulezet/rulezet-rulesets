rule sig_20160308_b3b69b3cced577526340424d8aee73d1 {
  meta:
    description = "datamaliciousorder - file 20160308_b3b69b3cced577526340424d8aee73d1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b055845dd3d51d993f3951611d858443f46402ab400faa3b0fbe799f0535bc9"

  strings:
    $s1  = "height[currentTarget] = ((1 ^ attaches) - 1);" fullword ascii
    $s2  = "xhrSupported[events + timeoutTimer](trim, createElement + beforeunload + scriptCharset + option + createDocumentFragment + rloca" ascii
    $s3  = "while (xhrSupported[dataFilter + each + tokens] < (Math.pow((37 - setAttribute), (162, curElem)) - (5 & amd))) {" fullword ascii
    $s4  = "sSelector + requestHeadersNames) + unqueued + fail + charset + binary + finish;" fullword ascii
    $s5  = "styles[namespaces + setOffset](xhrSupported[host + tokens + multipleContexts + serializeArray + contextBackup + w + setup]);" fullword ascii
    $s6  = "lProtocol + getBoundingClientRect + values + extra, !((((1 * pageX) & (198, pageX)) + ((1 + ((pageX | 1) ^ (assert - 39))) + ((m" ascii
    $s7  = "col[username + isTrigger][remove](((computeStyleTests * 14 + stopPropagation) / (26 | keyCode)));" fullword ascii
    $s8  = "documentIsHTML = rreturn[isWindow + types + focus + concat + parentsUntil + url + original + clearQueue + serializeArray](matche" ascii
    $s9  = "xhrSupported[events + timeoutTimer](trim, createElement + beforeunload + scriptCharset + option + createDocumentFragment + rloca" ascii
    $s10 = "col = (((205, selectedIndex, 167) ^ attaches * 5 * amd), (((9367 / keyCode) / (24 | amd)), this));" fullword ascii
    $s11 = "props = col[completeDeferred + queue + isTrigger];" fullword ascii
    $s12 = "xhrSupported = col[boxSizingReliableVal + div][winnow + pageXOffset + opt](duration + realStringObj + rinputs);" fullword ascii
    $s13 = "trim = \"GET\";" fullword ascii
    $s14 = "original = \"ntSt\", rinputs = \"TP\", opt = \"ject\", events = \"op\", host = \"R\", createElement = \"h\";" fullword ascii
    $s15 = "styles = col[eventHandle + rpseudo + finish + div][cssNormalTransform + capName + getResponseHeader](resolveWith + andSelf + isT" ascii
    $s16 = "once = 50, pageX = 1, getResponseHeader = \"ct\", fn = \"C\", stopImmediatePropagation = \"Ru\", realStringObj = \".XMLHT\";" fullword ascii
    $s17 = "styles = col[eventHandle + rpseudo + finish + div][cssNormalTransform + capName + getResponseHeader](resolveWith + andSelf + isT" ascii
    $s18 = "rigger + top);" fullword ascii
    $s19 = "col[hasOwn + classCache][parts + fx](((94 ^ once) - 2 * curElem * 2));" fullword ascii
    $s20 = "fadeIn = stopImmediatePropagation + after;" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}