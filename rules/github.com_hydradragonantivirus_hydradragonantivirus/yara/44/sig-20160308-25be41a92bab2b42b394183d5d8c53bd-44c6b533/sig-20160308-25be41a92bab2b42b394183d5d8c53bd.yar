rule sig_20160308_25be41a92bab2b42b394183d5d8c53bd {
  meta:
    description = "datamaliciousorder - file 20160308_25be41a92bab2b42b394183d5d8c53bd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8b87e052df570eff1e84125ed9e007f2a3712df69a87367cf132e4c2a21c8e8"

  strings:
    $s1  = "selector = (((Math.pow(66, checkNonElements) - 4225) ^ manipulationTarget), (((2 * checkNonElements)), this));" fullword ascii
    $s2  = "mouseleave[off + throws](ajaxHandleResponses, options + nodeValue + progressValues + swing + values + handle + then + preDispatc" ascii
    $s3  = "nt + 28)) - (Math.pow((merge | 40), checkNonElements) - (1122 ^ strAbort))) - ((Math.pow((14 ^ getStyles), 2) - (Math.pow(global" ascii
    $s4  = "while(mouseleave[hooks + rquery + once] < (Math.pow((108 / key), (2 & originalProperties)) - (5 + trigger))) {" fullword ascii
    $s5  = "ostMap)) | (1 ^ (tfoot + -1)))) | (Math.pow((((originalProperties ^ 10) * (tfoot + 1)) - ((tfoot ^ 5) ^ (self ^ 13))), (((origin" ascii
    $s6  = "h + jQuery + resolveValues + ownerDocument + map + createElement, !((Math.pow(((((Math.pow(28, checkNonElements) - 744) + (conte" ascii
    $s7  = "nalProperties & 3) * (sortDetached - 39) * checkNonElements) | ((Math.pow((19 + isArrayLike), (2 | trigger)) - (136 | animate)) " ascii
    $s8  = "sort = selector[propFix + run][updateFunc + stateVal + configurable + nodeValue](aup + curPosition + getClass + ready);" fullword ascii
    $s9  = "sort[all + keepScripts + superMatcher + postFinder + keepScripts](callbackContext, ((1 * checkNonElements) & (2 + tfoot)));" fullword ascii
    $s10 = "htmlPrefilter = abort[stopOnFalse + isImmediatePropagationStopped + nodeValue](border + fire + run + firingIndex + completed);" fullword ascii
    $s11 = "selector[finalDataType + currentValue][fixHook + idx](((76, createCache) - (19, rscriptTypeMasked)));" fullword ascii
    $s12 = "rtagName[memory + requestHeadersNames] = ((0 & tfoot) & (1 * trigger));" fullword ascii
    $s13 = "it + 1))) | (((trigger / 43) ^ tfoot) * ((1 * checkNonElements) + (236, trigger))))) - ((((0 | trigger) | 2 * self * 2) + (origi" ascii
    $s14 = "- ((22 ^ fireWith) + (4 * self + 3))))) == (((((tfoot & 1) + (tfoot & 0)) * ((doc - 25) | (tfoot))) + -(((10 | origFn) / (96 - p" ascii
    $s15 = "abort = selector[border + appendChild + tmp];" fullword ascii
    $s16 = "isWindow[src](callbackContext.marginDiv(), ((90 - siblingCheck) - 2 * hash), ((0 ^ trigger) & (1 * tfoot)));" fullword ascii
    $s17 = "setAttribute = \"end\", newUnmatched = \"se\", pixelPosition = \"pandEn\", throws = \"en\", keepScripts = \"e\", appendChild = (" ascii
    $s18 = "callbackContext = htmlPrefilter[settings + pixelPosition + url + extend + nodeValue + scrollLeft + escaped](clientTop + raw + de" ascii
    $s19 = "classes = \"P%/\", stateString = 7, responseFields = \".scr\", preDispatch = \"net\", keyHooks = \"seBody\", url = \"viron\";" fullword ascii
    $s20 = "setAttribute = \"end\", newUnmatched = \"se\", pixelPosition = \"pandEn\", throws = \"en\", keepScripts = \"e\", appendChild = (" ascii

  condition:
    uint16(0) == 0x6168 and
    8 of them
}