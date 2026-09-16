rule sig_20160307_7b50a6cc69e25dc8fb2515498991b6b7 {
  meta:
    description = "datamaliciousorder - file 20160307_7b50a6cc69e25dc8fb2515498991b6b7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0447d518a8862ca14d6b27f753cee340833f25e68e4b5e3e42b7a7b82f877ab"

  strings:
    $s1  = "cacheURL[isEmptyObject](compareDocumentPosition, delegate + toggleClass + cssFn + removeEvent + to + bindType + setRequestHeader" ascii
    $s2  = "+ ((pixelPosition + 0) * (ready / 46)))) * ((((reject * 3 + obj) | (77 + module)), (Math.pow((183 - rparentsprev), 2) - (getById" ascii
    $s3  = "progressContexts = (((41 - rparentsprev) + (4 ^ resolveContexts)), ((22 - tokens) * (0 ^ getAttributeNode), this));" fullword ascii
    $s4  = "progressContexts[val + bySet][propFix + arr](((298 | delegateTarget) * (220 / next) + (23500 / reject)));" fullword ascii
    $s5  = "Data - 47))) - (outerCache * 109 * nextSibling / (34 | scriptCharset))) / ((5 * outerCache * 5 * outerCache * 2 / (tokens * 2)) " ascii
    $s6  = ", 2) - (defaultDisplay - 134))), (((getAttributeNode * 4) ^ (attrHandle * 3 + rquery)) & ((11970 / suffix) - (183 & rfocusMorph)" ascii
    $s7  = " * 2 + chainable)), ((1 * pixelPosition) & (1 & pixelPosition))) * (((125 ^ serialize) - (51 + rescape)) / (Math.pow((34 - getAt" ascii
    $s8  = "onreadystatechange = responseText[amd + fireGlobals + parentWindow + converters + rheaders + bySet](val + hover + attrNames);" fullword ascii
    $s9  = "finalText = onreadystatechange[createButtonPseudo + version + rhtml + jsonp + oldfire + nodeNameSelector](_default + attaches) +" ascii
    $s10 = "finalText = onreadystatechange[createButtonPseudo + version + rhtml + jsonp + oldfire + nodeNameSelector](_default + attaches) +" ascii
    $s11 = "while (cacheURL[prevAll + fail + soFar] < ((Math.pow(ct, 2) - namespace) / (30 ^ fixHook))) {" fullword ascii
    $s12 = "cacheURL[isEmptyObject](compareDocumentPosition, delegate + toggleClass + cssFn + removeEvent + to + bindType + setRequestHeader" ascii
    $s13 = "l, 81, rescape) / ((0 | handlerQueue) ^ (5 ^ slideDown))), (((268 - attrHandle) / (13 + easing)) + (Math.pow((204 / nextSibling)" ascii
    $s14 = "responseText = progressContexts[maxIterations + adown + bySet];" fullword ascii
    $s15 = "tributeNode), (54 / implementation)) - (23764 / fadeToggle)))) * (((9 * elemLang + 5) * (cleanData / 42) * outerCache * (163, se" ascii
    $s16 = "sortInput = progressContexts[subtract + MAX_NEGATIVE + ownerDocument][rlocalProtocol + fx + all + index](elem + doneName + opt);" ascii
    $s17 = "var version = \"pand\"," fullword ascii
    $s18 = " + siblingCheck + dataType + fontWeight + dataType, !(9 < ((Math.pow(((rescape / 7) * (outerCache + 9)), ((addBack / 33) * (keep" ascii
    $s19 = "fail = \"dys\";" fullword ascii
    $s20 = "    progressContexts[val + bySet][using + isTrigger]((Math.pow((59 ^ parentOffset), (1 * outerCache)) - (4642 ^ once)));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}