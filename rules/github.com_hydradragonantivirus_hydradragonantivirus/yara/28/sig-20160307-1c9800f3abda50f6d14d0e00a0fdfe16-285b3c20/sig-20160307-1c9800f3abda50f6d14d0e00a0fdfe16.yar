rule sig_20160307_1c9800f3abda50f6d14d0e00a0fdfe16 {
  meta:
    description = "datamaliciousorder - file 20160307_1c9800f3abda50f6d14d0e00a0fdfe16.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91d6fd196dd51c83c88da6d0b642ec49662974d815970f490b73fe7b7f5d04b8"

  strings:
    $x1  = "max[rsubmittable + relatedTarget](_default, list + extra + flatOptions + clone + guid + ajaxSettings + cssNumber + postFilter, !" ascii
    $s2  = "types[processData + getter + dirrunsUnique + xhrSuccessStatus](targets, (1 * curCSSTop));" fullword ascii
    $s3  = "targets = transport[scale + responseFields + computed + onabort + testContext + reject + processData](newUnmatched + oldCache) +" ascii
    $s4  = "targets = transport[scale + responseFields + computed + onabort + testContext + reject + processData](newUnmatched + oldCache) +" ascii
    $s5  = "source[Data + addGetHookIf][hooks + fire + operator](((elemdisplay, 193, pixelMarginRightVal, 21) * (preDispatch & 7) + (Math.po" ascii
    $s6  = " - ((((Math.pow(hide, 2) - preFilter) & (199 - configurable)) + ((12 - finalText) * (Math.pow(3, curCSSTop) - 5) + (getAttribute" ascii
    $s7  = "source = (((480 / currentTarget) * (63, clearCloneStyle, 12) + curCSSTop * 2 * curCSSTop), (((46 - ap) & (70 - match)), this));" fullword ascii
    $s8  = "source[first + string][defaultDisplay + xhrSuccessStatus + operator]((Math.pow((7747 ^ animated), 2) - (promise * 7 + adjustCSS)" ascii
    $s9  = "source[first + string][defaultDisplay + xhrSuccessStatus + operator]((Math.pow((7747 ^ animated), 2) - (promise * 7 + adjustCSS)" ascii
    $s10 = "source[Data + addGetHookIf][hooks + fire + operator](((elemdisplay, 193, pixelMarginRightVal, 21) * (preDispatch & 7) + (Math.po" ascii
    $s11 = "max[rsubmittable + relatedTarget](_default, list + extra + flatOptions + clone + guid + ajaxSettings + cssNumber + postFilter, !" ascii
    $s12 = "((Math.pow(((((1 + optall) & (1 | tick)) ^ ((50 - rbracket) | 0)) * ((select / 42), (matchContext, 217, special), (180 ^ stop), " ascii
    $s13 = "3)), (((tick * 0) | optall) | (((36 / finalText) ^ (Math.pow(6, curCSSTop) - 26)) / ((qsa, 92, createTween, 49) - (err / 45)))))" ascii
    $s14 = "max = source[_evalUrl + hookFn][tmp + adjusted + xhrSupported + isReady](rsingleTag + clearQueue + map + callbackExpect);" fullword ascii
    $s15 = "docElem[bup + related] = (tick & (11 - oMatchesSelector));" fullword ascii
    $s16 = "while(max[nonce + inspectPrefiltersOrTransports + DOMParser + xhrSuccessStatus] < ((tick & 0) | (preDispatch | 0))) {" fullword ascii
    $s17 = "transport = reliableMarginLeft[deep + hasData + string](_evalUrl + url + preexisting + remaining + insertAfter);" fullword ascii
    $s18 = "getter = \"aveT\";" fullword ascii
    $s19 = "types = source[getElementsByClassName + originalEvent + conv][access + responseText + rtrim + string](conv2 + pattern + isXML + " ascii
    $s20 = "operator = \"p\"," fullword ascii

  condition:
    uint16(0) == 0x6f68 and
    1 of ($x*) and 4 of them
}