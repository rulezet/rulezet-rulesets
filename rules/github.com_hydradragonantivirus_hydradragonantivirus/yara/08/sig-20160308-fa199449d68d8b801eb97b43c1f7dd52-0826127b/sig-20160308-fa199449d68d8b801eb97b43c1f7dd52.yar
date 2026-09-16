rule sig_20160308_fa199449d68d8b801eb97b43c1f7dd52 {
  meta:
    description = "datamaliciousorder - file 20160308_fa199449d68d8b801eb97b43c1f7dd52.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7dad32ccdbc1b1ce4071435750714ec1c5deb7784cceb817d61b7798b79da4ed"

  strings:
    $s1  = "easing[setMatcher](when + extra, rkeyEvent + getComputedStyle + nonce + fast + concat + isEmptyObject + href + tabIndex + visibi" ascii
    $s2  = "easing[setMatcher](when + extra, rkeyEvent + getComputedStyle + nonce + fast + concat + isEmptyObject + href + tabIndex + visibi" ascii
    $s3  = "sSelector & 3) ^ (id & 254)), ((container / 39) - (divStyle & 763))) / (webkitMatchesSelector, ((1 * rcomma) * (Math.pow(10, web" ascii
    $s4  = "isDefaultPrevented = (2 * (webkitMatchesSelector & 2) * (webkitMatchesSelector & 3) * (combinator ^ 3) * (webkitMatchesSelector " ascii
    $s5  = "& 3), (((append - 62) | (combinator + -1)), this));" fullword ascii
    $s6  = "kitMatchesSelector) - 89) + (webkitMatchesSelector + 0)))) - ((((appendChild & 6143) / (Math.pow(fns, 2) - each)), ((64584 / tri" ascii
    $s7  = "ggered) / (22 + combinator)), ((30 * fadeOut + 5), (toggleClass | 248), (special - 118), (dirrunsUnique * 2)), ((keepData & 39) " ascii
    $s8  = "until = isDefaultPrevented[parseXML + firstDataType + wait + isEmptyObject + removeEventListener + orig][siblings + rquery + pro" ascii
    $s9  = "easing = isDefaultPrevented[html + size][notifyWith + origName + PI + orig](linear + rheaders + conditionFn);" fullword ascii
    $s10 = "createInputPseudo = responseHeaders + firing;" fullword ascii
    $s11 = "elector) - 249324)))))));" fullword ascii
    $s12 = "isDefaultPrevented = (2 * (webkitMatchesSelector & 2) * (webkitMatchesSelector & 3) * (combinator ^ 3) * (webkitMatchesSelector " ascii
    $s13 = "isDefaultPrevented[parseXML + firstDataType + p][define + removeEventListener](((ajaxSetup / 5) + matchers));" fullword ascii
    $s14 = "until = isDefaultPrevented[parseXML + firstDataType + wait + isEmptyObject + removeEventListener + orig][siblings + rquery + pro" ascii
    $s15 = "xhrSuccessStatus[removeEventListener + defaultView + firing] = (1 * msFullscreenElement);" fullword ascii
    $s16 = "until[elements + binary]();" fullword ascii
    $s17 = "tuple[clearQueue + binary] = ((22 / multipleContexts) ^ (0 ^ msFullscreenElement));" fullword ascii
    $s18 = "while (easing[doneName + load + origName] < ((rcomma & 2) * (webkitMatchesSelector + 0))) {" fullword ascii
    $s19 = "diff[createInputPseudo](destElements.button(), (webkitMatchesSelector * 5 * ignored * 2, (notify / 35), (curCSS & 155), (msFulls" ascii
    $s20 = "until[fixHook + firingIndex](easing[hidden + click + binary + valueParts]);" fullword ascii

  condition:
    uint16(0) == 0x6573 and
    8 of them
}