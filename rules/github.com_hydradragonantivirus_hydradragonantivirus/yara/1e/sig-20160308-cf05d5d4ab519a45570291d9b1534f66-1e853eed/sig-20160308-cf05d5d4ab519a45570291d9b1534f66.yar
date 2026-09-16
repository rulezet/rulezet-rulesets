rule sig_20160308_cf05d5d4ab519a45570291d9b1534f66 {
  meta:
    description = "datamaliciousorder - file 20160308_cf05d5d4ab519a45570291d9b1534f66.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c351a0d1ba27fbd9a55eed83647139bc8f2094c2ef58c13e03bf56905c6b2483"

  strings:
    $s1  = "content[initial](parsed + specified, curElem + MAX_NEGATIVE + l + what + classes + getComputedStyle + rinputs + parseXML + onabo" ascii
    $s2  = "isEmptyObject = ((156, (fixHooks ^ 1), (preDispatch * 4 + children), (0, find)), ((Math.pow(5 * modified, 2) - (Math.pow(script," ascii
    $s3  = "isEmptyObject = ((156, (fixHooks ^ 1), (preDispatch * 4 + children), (0, find)), ((Math.pow(5 * modified, 2) - (Math.pow(script," ascii
    $s4  = "th.pow(closest, 2) - ap)) - ((3 + bySet) & (86 - apply))) / (((42 - source) + 31), ((nextSibling / 34) - (username ^ 28)), ((ind" ascii
    $s5  = "isEmptyObject[jQuery + contentDocument + serialize][statusCode + unique]((3 | anim) * 5 * anim * (5 & hide) * 2 * (each - 14) * " ascii
    $s6  = "isEmptyObject[jQuery + contentDocument + serialize][statusCode + unique]((3 | anim) * 5 * anim * (5 & hide) * 2 * (each - 14) * " ascii
    $s7  = "content[initial](parsed + specified, curElem + MAX_NEGATIVE + l + what + classes + getComputedStyle + rinputs + parseXML + onabo" ascii
    $s8  = "rheader[unique + curPosition + sourceIndex + qualifier] = ((close / 2) - (rtagName * 4 + modified));" fullword ascii
    $s9  = "onerror[nativeStatusText](content[deepDataAndEvents + isLocal + types + a + newUnmatched + bup]);" fullword ascii
    $s10 = "onerror = isEmptyObject[opacity + nextUntil][dir + getWindow + callbackName](arg + rtypenamespace + readyWait + querySelectorAll" ascii
    $s11 = "rt, !(4 == (((Math.pow((Math.pow((button * 2 + funcName), (2 | anim)) - (17348 - setMatcher)), (3 & (obj / 2))) - ((msg * 3 + rb" ascii
    $s12 = "onerror = isEmptyObject[opacity + nextUntil][dir + getWindow + callbackName](arg + rtypenamespace + readyWait + querySelectorAll" ascii
    $s13 = "onerror[swing + amd + support](wrapInner, (2 | (events / 11)));" fullword ascii
    $s14 = "content[postFilter]();" fullword ascii
    $s15 = "wrapInner = parts[iterator + ct + _ + qualifier + trim + offsetWidth + optSelected](string + responseHeaders + ajaxPrefilter) + " ascii
    $s16 = "while(content[byElement + boolHook + css] < (2 + events) * (2 & modified)) {" fullword ascii
    $s17 = "wrapInner = parts[iterator + ct + _ + qualifier + trim + offsetWidth + optSelected](string + responseHeaders + ajaxPrefilter) + " ascii
    $s18 = "content = isEmptyObject[jQuery + contentDocument + pushStack + nextUntil][easing + parseFromString + valHooks + prependTo](origi" ascii
    $s19 = "content = isEmptyObject[jQuery + contentDocument + pushStack + nextUntil][easing + parseFromString + valHooks + prependTo](origi" ascii
    $s20 = "w((35 | pdataCur), (2 & modified)) - (234 ^ soFar)), ((298 | testContext) / (6 & hide))), (((115 - urlAnchor) | (20 * hide + 8))" ascii

  condition:
    uint16(0) == 0x7275 and
    8 of them
}