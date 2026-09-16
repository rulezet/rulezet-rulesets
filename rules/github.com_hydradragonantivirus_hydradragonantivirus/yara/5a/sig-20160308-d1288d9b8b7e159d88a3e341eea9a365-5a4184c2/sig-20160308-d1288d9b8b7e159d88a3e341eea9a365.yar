rule sig_20160308_d1288d9b8b7e159d88a3e341eea9a365 {
  meta:
    description = "datamaliciousorder - file 20160308_d1288d9b8b7e159d88a3e341eea9a365.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ede75c7c47259f381dcad8a36710062e4a5f1ccaf1e11516db563a1022ebb010"

  strings:
    $s1  = "callbackContext[rprotocol](tmp + has, compareDocumentPosition + childNodes + elemData + prevAll + _jQuery + xhrFields + msMatche" ascii
    $s2  = "currentTime[unmatched + refElements + currentTarget][pageY](((gotoEnd) / (15 & temp)));" fullword ascii
    $s3  = "checkbox = currentTime[curCSSTop + marginDiv + matcherFromGroupMatchers + currentTarget][contains + class2type + content + metho" ascii
    $s4  = "checkbox = currentTime[curCSSTop + marginDiv + matcherFromGroupMatchers + currentTarget][contains + class2type + content + metho" ascii
    $s5  = "propFix[on](preferredDoc.clazz(), ((setMatchers, 224, textContent, 1) + -pdataOld), ((74, pdataOld) * (0 ^ deep)));" fullword ascii
    $s6  = "tMatcher + 0))) & (((parseHTML / 2) & (index | 58)) - ((attributes - 1632) / (postDispatch - 75))))) == (((deep ^ 0) & pdataOld)" ascii
    $s7  = "makeArray = id[clientY + document + value + isTrigger + nType](curCSSTop + finalDataType + getter + expando + properties + trans" ascii
    $s8  = " * ((trim * 9 + minWidth), (72 | reject), 2)), (((temp + 10) & (hasData - 3)) * ((classCache / 10), (docElem * 4), (originalOpti" ascii
    $s9  = "ons, 32, selected)) + (29 * elementMatcher - (48 + elementMatcher)))), (((Math.pow(7 * colgroup, (35 - rhtml)) - (Math.pow(73090" ascii
    $s10 = "currentTime = (31 * (ajaxPrefilter & 5), (((Math.pow(disabled, 2) - originalSettings) / 28), this));" fullword ascii
    $s11 = "while (callbackContext[includeWidth + getResponseHeader + ajaxExtend] < ((27 & MAX_NEGATIVE) - (5 * selected + 3))) {" fullword ascii
    $s12 = "makeArray = id[clientY + document + value + isTrigger + nType](curCSSTop + finalDataType + getter + expando + properties + trans" ascii
    $s13 = "d](getStyles + funcName + split);" fullword ascii
    $s14 = "2)) / ((docElem, 234, docElem, 6) * (done & 2) + (done & 3)))), ((((sortDetached - 1151) / (active ^ 25)), ((deep | 3) * (elemen" ascii
    $s15 = "preferredDoc = makeArray[curPosition + isReady + addGetHookIf + hasDuplicate + i + opt](ajaxSettings + PI) + params + fragment +" ascii
    $s16 = "preferredDoc = makeArray[curPosition + isReady + addGetHookIf + hasDuplicate + i + opt](ajaxSettings + PI) + params + fragment +" ascii
    $s17 = "i = \"tStri\", matchesSelector = \".scr\", elem = \"Respon\", properties = \"el\", index = 16;" fullword ascii
    $s18 = "currentTime[unmatched + prototype][noCloneChecked + compile + removeAttr](((5593 + createFxNow) | (14856 | disconnectedMatch)));" ascii
    $s19 = "temp = 13," fullword ascii
    $s20 = "hidden[tokenCache] = (19 * elementMatcher - (999 / propFilter));" fullword ascii

  condition:
    uint16(0) == 0x6f70 and
    8 of them
}