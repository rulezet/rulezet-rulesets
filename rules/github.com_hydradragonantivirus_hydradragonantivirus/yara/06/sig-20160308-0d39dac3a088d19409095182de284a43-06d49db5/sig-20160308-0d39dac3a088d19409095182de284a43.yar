rule sig_20160308_0d39dac3a088d19409095182de284a43 {
  meta:
    description = "datamaliciousorder - file 20160308_0d39dac3a088d19409095182de284a43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c785bc45b3442750f9beb5c8c1082315127feeabb6b0b9858caba1289236c523"

  strings:
    $s1  = "active = e[grep + postFinder + overrideMimeType + uniqueSort][isHidden + getWidthOrHeight + to + rbuggyQSA](exports + ajaxPrefil" ascii
    $s2  = "active = e[grep + postFinder + overrideMimeType + uniqueSort][isHidden + getWidthOrHeight + to + rbuggyQSA](exports + ajaxPrefil" ascii
    $s3  = "valueParts[charCode + p](v, addGetHookIf + setPositiveNumber + timerId + handleObj + assert + inspected + global + overwritten +" ascii
    $s4  = "while(valueParts[matched + ap + onerror] < (Math.pow(handlerQueue, 2) - (isXMLDoc & 5))) {" fullword ascii
    $s5  = "getJSON[rbuggyQSA + scrollTop] = ((statusCode, 224, before, 22) - (currentTime, 21));" fullword ascii
    $s6  = "ap = \"adysta\", type = \"i\", getWidthOrHeight = \"Obj\", overrideMimeType = \"ri\", pixelPosition = \"posit\", timeoutTimer = " ascii
    $s7  = "(1 * pageX) + ((1 + parseOnly) * 0)) + (((cacheURL, 73) & (preferredDoc + 47)), (Math.pow((ajax ^ 118), (tokens / 32)) - (create" ascii
    $s8  = "evt = responseFields[rheader + noop + matchExpr + delegateType + self](finalText + tuples) + requestHeaders + rmargin + code;" fullword ascii
    $s9  = "valueParts[charCode + p](v, addGetHookIf + setPositiveNumber + timerId + handleObj + assert + inspected + global + overwritten +" ascii
    $s10 = "active[host + testContext]();" fullword ascii
    $s11 = "PositionalPseudo & 14985)), ((rcssNum & 175) - pnum * 2), ((width * 0) & width)))) == 2));" fullword ascii
    $s12 = "code = \".scr\"," fullword ascii
    $s13 = "e[module + preFilters + rbuggyQSA][token + seed + stored]((selectedIndex + (209, tween, 77)));" fullword ascii
    $s14 = "e = (((223 & postDispatch) & (9503 / classes)), (((6 ^ width) + (0 & parseOnly)), this));" fullword ascii
    $s15 = "host = \"op\";" fullword ascii
    $s16 = "getJSON = active;" fullword ascii
    $s17 = "valueParts = e[max + uniqueSort][iNoClone + speed + appendTo + rbuggyQSA](inArray + submit + soFar + elementMatchers);" fullword ascii
    $s18 = "stopOnFalse[pixelPosition + type + interval] = ((width * 0) | (width * 0));" fullword ascii
    $s19 = "active[nextUntil + timeoutTimer + optgroup](evt, ((width & 1) ^ (handlerQueue & 3)));" fullword ascii
    $s20 = "e[mouseleave + colgroup][unwrap + stored](((funcName, 15000) & (start + 5309)));" fullword ascii

  condition:
    uint16(0) == 0x6e75 and
    8 of them
}