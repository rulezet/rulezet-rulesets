rule sig_20160308_a09ac3d96a1917b3bd1daed75c5a4996 {
  meta:
    description = "datamaliciousorder - file 20160308_a09ac3d96a1917b3bd1daed75c5a4996.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "164fd6d0837af49b1347d5a270a76228f9131cb5e43c702838943118c58be098"

  strings:
    $s1  = "mozMatchesSelector[readyState](xml + events, mapped + argument + rlocalProtocol + animate + createButtonPseudo + serializeArray " ascii
    $s2  = "headers = \"%TEMP%\", augmentWidthOrHeight = 160, progressContexts = \"w\", andSelf = 29, sort = \"ect\";" fullword ascii
    $s3  = "dataTypeExpression[width + scripts + responseHeadersString + dispatch + empty](args, 2);" fullword ascii
    $s4  = "handlers[stopQueue + token + original][propName + createTextNode]((Math.pow((string - 6277), (reliableMarginLeftVal - 50)) - (un" ascii
    $s5  = "handlers[stopQueue + token + original][propName + createTextNode]((Math.pow((string - 6277), (reliableMarginLeftVal - 50)) - (un" ascii
    $s6  = " * 17 - (once))) - (((0 | evt) - (Math.pow(38, handle) - 1393)), ((Math.pow(bindType, 2) - clientTop) / (4 | bp)))) + ((((31 & o" ascii
    $s7  = "args = cssNormalTransform[_jQuery + write + Data + setTimeout + size + responseContainer + rquickExpr](headers + rsubmitterTypes" ascii
    $s8  = "+ fireGlobals + button + optDisabled + resolveContexts, !((((((rsibling, 97, augmentWidthOrHeight) - (1976 / get)) - (2 * handle" ascii
    $s9  = "getAttributeNode = handlers[newUnmatched + hidden + ifModified];" fullword ascii
    $s10 = "  handlers[newUnmatched + keys][postFinder + setMatchers]((5 * classes * 3 + (raw - 75)));" fullword ascii
    $s11 = "handlers = (((272 & createInputPseudo) - (Math.pow(37, handle) - 1311)), (((self, 92, apply, 440) / (using / 35)), this));" fullword ascii
    $s12 = "dataTypeExpression[progressContexts + hidden + compareDocumentPosition](mozMatchesSelector[deepDataAndEvents + radioValue + isFu" ascii
    $s13 = "while(mozMatchesSelector[list + stopOnFalse + initial] < (Math.pow(refElements, (2 + overwritten)) - (29 - onload))) {" fullword ascii
    $s14 = "dataTypeExpression[progressContexts + hidden + compareDocumentPosition](mozMatchesSelector[deepDataAndEvents + radioValue + isFu" ascii
    $s15 = "nce) ^ (Math.pow(3, handle) - 5)) * ((handle ^ 12) - (refElements ^ 8)) + ((v - 52) & (slow - 25))), (((copyIsArray | 52)) & (Ma" ascii
    $s16 = "tion / 50) | (obj + 3))), (((overwritten ^ 1) * (overwritten ^ 3)) ^ ((writable) ^ 0)))) == (Math.pow((((map * 2 + writable) - (" ascii
    $s17 = " fadeTo + checkClone + disableScript + body);" fullword ascii
    $s18 = "mozMatchesSelector = handlers[newUnmatched + then + outermost][marginLeft + list + pnum + curLeft + valueIsBorderBox](tweeners +" ascii
    $s19 = "args = cssNormalTransform[_jQuery + write + Data + setTimeout + size + responseContainer + rquickExpr](headers + rsubmitterTypes" ascii
    $s20 = "cssNormalTransform = getAttributeNode[marginLeft + css + noConflict + sort](newUnmatched + specified + unwrap + cssShow);" fullword ascii

  condition:
    uint16(0) == 0x6172 and
    8 of them
}