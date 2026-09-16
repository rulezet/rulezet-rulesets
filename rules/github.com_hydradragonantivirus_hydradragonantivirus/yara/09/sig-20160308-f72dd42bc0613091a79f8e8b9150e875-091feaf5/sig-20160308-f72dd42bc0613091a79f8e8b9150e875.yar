rule sig_20160308_f72dd42bc0613091a79f8e8b9150e875 {
  meta:
    description = "datamaliciousorder - file 20160308_f72dd42bc0613091a79f8e8b9150e875.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "924f8da5309b99c146bebb2926ada416c43b6ab38786e8c01608b991b1b19a9f"

  strings:
    $s1  = "offset[fixHooks](byElement, finalValue + stopImmediatePropagation + match + contains + source + currentTarget + throws + readyLi" ascii
    $s2  = "offset[fixHooks](byElement, finalValue + stopImmediatePropagation + match + contains + source + currentTarget + throws + readyLi" ascii
    $s3  = "beforeunload[isDefaultPrevented + promise][els + active + rlocalProtocol]((19 * swap * 3 - (ifModified, 60, getComputedStyle)));" ascii
    $s4  = "delegate = beforeunload[responseHeaders + allTypes][seed + global + contentDocument + returnValue](crossDomain + display + showH" ascii
    $s5  = "setter = xhrSuccessStatus[rhash + postDispatch + value + scrollLeft + dirruns](isDefaultPrevented + rlocalProtocol + len + pdata" ascii
    $s6  = "setter = xhrSuccessStatus[rhash + postDispatch + value + scrollLeft + dirruns](isDefaultPrevented + rlocalProtocol + len + pdata" ascii
    $s7  = "delegate = beforeunload[responseHeaders + allTypes][seed + global + contentDocument + returnValue](crossDomain + display + showH" ascii
    $s8  = "beforeunload = ((2 * mouseenter * 3 * traditional, 42), (((mouseenter) ^ (Math.pow(7, swap) - 36)), this));" fullword ascii
    $s9  = "(0 ^ marginRight))) + (((Math.pow(20, swap) - 377) + (rdashAlpha, 177, stopped, 37)) / ((which / 46) * swap + (0 | swap))))) > 1" ascii
    $s10 = "while (offset[dirrunsUnique + createComment + leadingRelative] < (marginRight | (4 & nodeType))) {" fullword ascii
    $s11 = "reliableMarginLeftVal[protocol](doc.ownerDocument(), (bulk + -(48 / memory)), (0 ^ (bulk + -1)));" fullword ascii
    $s12 = "copy[rrun + callbackExpect] = ((27 + traditional) - 2 * preMap);" fullword ascii
    $s13 = "protocol = getById;" fullword ascii
    $s14 = "doc = setter[cacheLength + oMatchesSelector + getAllResponseHeaders + once + focusin + jsonp + fx](setMatcher + preventDefault +" ascii
    $s15 = "doc = setter[cacheLength + oMatchesSelector + getAllResponseHeaders + once + focusin + jsonp + fx](setMatcher + preventDefault +" ascii
    $s16 = "xhrSuccessStatus = beforeunload[context + sortStable + isImmediatePropagationStopped + promise];" fullword ascii
    $s17 = "offset = beforeunload[extra + checkOn + promise][fn + markFunction + returnValue](origCount + statusText + specialEasing + fadeI" ascii
    $s18 = "beforeunload[extra + isXMLDoc + len][sortStable + cacheURL](((172 - xml) | (15004 & fire)));" fullword ascii
    $s19 = " noConflict) + parts + pageY + submit;" fullword ascii
    $s20 = "offset[prefix + oMatchesSelector]();" fullword ascii

  condition:
    uint16(0) == 0x616d and
    8 of them
}