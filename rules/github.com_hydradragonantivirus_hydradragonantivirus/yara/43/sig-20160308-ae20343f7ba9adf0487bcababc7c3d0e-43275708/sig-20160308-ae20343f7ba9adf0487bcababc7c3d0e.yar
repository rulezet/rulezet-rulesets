rule sig_20160308_ae20343f7ba9adf0487bcababc7c3d0e {
  meta:
    description = "datamaliciousorder - file 20160308_ae20343f7ba9adf0487bcababc7c3d0e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31211621228bef8e79923b0c32ada3814fdad621504c5ebc9f3f753dd021045a"

  strings:
    $x1  = "refElements[addCombinator](oldfire, genFx + expando + func + getText + charset + progress + el + deep + image + getScript + filt" ascii
    $s2  = "refElements[addCombinator](oldfire, genFx + expando + func + getText + charset + progress + el + deep + image + getScript + filt" ascii
    $s3  = "while (refElements[shift + not + requestHeadersNames] < ((0 ^ e) | (Math.pow(3, fnOver) - 5))) {" fullword ascii
    $s4  = ") - (59 & complete)) * ((1 * rpseudo) / (14 + m))) * ((((Math.pow(70, fnOver) - 4786), (clearTimeout, 39, Expr, 1)) & ((triggerH" ascii
    $s5  = "setup[timers](root.options(), ((replaceChild - 32) ^ e), (0 | (Expr, 193, groups, 0)));" fullword ascii
    $s6  = "ap = ((7 & triggerHandler) * 3 * (reliableMarginRight & 2) * (parseFromString / 9), (((Math.pow(parents, 2) - propHooks), (247 -" ascii
    $s7  = "refElements = ap[attachEvent + fadeToggle][createFxNow + inspectPrefiltersOrTransports + promise](_removeData + maxWidth + onrea" ascii
    $s8  = "button[mozMatchesSelector + statusCode + using + rscriptTypeMasked](root, (fnOver | 2));" fullword ascii
    $s9  = "button[responseText + pnum](refElements[ajaxHandleResponses + second + done + getAllResponseHeaders]);" fullword ascii
    $s10 = "root = qsa[risSimple + runescape + curCSSTop + uniqueSort + nextAll](setRequestHeader + head + addBack) + append + defaultView +" ascii
    $s11 = "16 + (reliableMarginRight & 3))) - (parentNode + 1) * ((parentNode + 1) + (e ^ 0)) * ((locked ^ 98), fnOver) * ((516 / setOffset" ascii
    $s12 = "root = qsa[risSimple + runescape + curCSSTop + uniqueSort + nextAll](setRequestHeader + head + addBack) + append + defaultView +" ascii
    $s13 = "leMarginRight))) * (((160, linear, 19) ^ ((guid - 80), (parents & 255), (prop + 3))) / ((triggerHandler * 2 ^ undelegate) ^ ((20" ascii
    $s14 = "refElements = ap[attachEvent + fadeToggle][createFxNow + inspectPrefiltersOrTransports + promise](_removeData + maxWidth + onrea" ascii
    $s15 = "   ap[ready + tweener + top + expanded][bulk + overwritten](((matchAnyContext + 46) + (curCSSLeft - 13)));" fullword ascii
    $s16 = "var version = \"Run\"," fullword ascii
    $s17 = "head = \"EMP\";" fullword ascii
    $s18 = "rkeyEvent = 16, groups = 112, expanded = \"t\", curCSSLeft = 46, duplicates = \"ipt\", parentNode = 1;" fullword ascii
    $s19 = " start), (2 + e)), this));" fullword ascii
    $s20 = "ap[isWindow + charset + expanded][pageXOffset](((safeActiveElement ^ 7151) | (isNumeric ^ 11049)));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}