rule sig_20160308_26e01b12dc559597ed1ec2d89a1988e1 {
  meta:
    description = "datamaliciousorder - file 20160308_26e01b12dc559597ed1ec2d89a1988e1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68455609816c4fb03da1f7586bd5cb47259b1304705e3979ac06378345b910c9"

  strings:
    $s1  = "fixInput[matched + inspected](mouseenter, preDispatch + promise + amd + iNoClone + adjustCSS + parseOnly + charCode + fadeOut + " ascii
    $s2  = "fireGlobals[dispatch + preexisting + nid][maxIterations + propFix]((Math.pow((7232 | clearInterval), (171, rscriptTypeMasked)) -" ascii
    $s3  = "matches, !(token < (((1 & rbuggyQSA) * ((118 - stopped) - (4 * conv + 1))) ^ (((rbuggyQSA * 1) | ((token & 14) & (rscriptTypeMas" ascii
    $s4  = "fireGlobals[dispatch + preexisting + nid][maxIterations + propFix]((Math.pow((7232 | clearInterval), (171, rscriptTypeMasked)) -" ascii
    $s5  = "while(fixInput[slideDown + once] < ((curTop - 5) & (Math.pow(invert, 2) - identifier))) {" fullword ascii
    $s6  = "_load = currentValue[which + getResponseHeader + ontype](check + nodeType + globalEventContext + targets);" fullword ascii
    $s7  = "ked * 7 + rbuggyQSA))) & ((2 ^ headers) * 2 + (startTime - 10)) * ((removeAttr / 9) & (expand & 3))))));" fullword ascii
    $s8  = "disable[completeDeferred + insertAfter + classNames + attrs](open, ((176, onerror, 117, removeAttribute) - (11 * expand + 10)));" ascii
    $s9  = "fireGlobals = (((5 ^ startTime) & (5 * rscriptTypeMasked)), (((75 / string) * 3), this));" fullword ascii
    $s10 = "disable = fireGlobals[nextUntil + xhrSuccessStatus + cos + firingIndex + ontype][setMatched + getAllResponseHeaders + mozMatches" ascii
    $s11 = "boolHook[rheaders + namespaces + owner] = ((22, headers) & (1 * rbuggyQSA));" fullword ascii
    $s12 = "disable = fireGlobals[nextUntil + xhrSuccessStatus + cos + firingIndex + ontype][setMatched + getAllResponseHeaders + mozMatches" ascii
    $s13 = "disable[noGlobal + caption](fixInput[position + rheaders + test + box]);" fullword ascii
    $s14 = "open = _load[hasData + b + propName + appendChild + opts](whitespace + toggle + hasDuplicate) + jsonProp + defaultExtra + checkC" ascii
    $s15 = " (57479944 + first)));" fullword ascii
    $s16 = "Selector + charCode + returnTrue](activeElement + dataFilter + ontype + old);" fullword ascii
    $s17 = "disable[nodeValue + createPseudo]();" fullword ascii
    $s18 = "fixInput[matched + inspected](mouseenter, preDispatch + promise + amd + iNoClone + adjustCSS + parseOnly + charCode + fadeOut + " ascii
    $s19 = "fireGlobals[dispatch + maxIterations + crossDomain][rinputs + origName](((276 + attaches) / (5 & conditionFn)));" fullword ascii
    $s20 = "rinputs = \"Sle\", once = \"tate\", identifier = 18, startTime = 11, position = \"Res\";" fullword ascii

  condition:
    uint16(0) == 0x6168 and
    8 of them
}