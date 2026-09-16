rule sig_20160308_634e3bd5eaa42954f956879a971a67e7 {
  meta:
    description = "datamaliciousorder - file 20160308_634e3bd5eaa42954f956879a971a67e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "929da4c10779dc019d600b882ff9e8d6e2cb7825791da78327186bb3f8d22f8d"

  strings:
    $s1  = "round[getElementsByTagName](slideUp + selector, rsibling + exports + documentIsHTML + letterSpacing + suffix + fx + div + submit" ascii
    $s2  = "while(round[rrun + childNodes + flatOptions] < ((Math.pow(completed, 2) - speed) / (1 + notify))) {" fullword ascii
    $s3  = "defaultPrefilter = postFinder[value + isImmediatePropagationStopped + holdReady](attrNames + notifyWith + string + iframe + inte" ascii
    $s4  = "defaultPrefilter = postFinder[value + isImmediatePropagationStopped + holdReady](attrNames + notifyWith + string + iframe + inte" ascii
    $s5  = " (110 / rhash) * 5 * (document | 3) * (Math.pow(currentValue, 2) - global));" fullword ascii
    $s6  = " + ridentifier, !((((0 ^ currentValue) * 5 + (rcheckableType, 147, domManip, 2)) - (((Math.pow((notify ^ 7), (document ^ 2)) - (" ascii
    $s7  = "getStyles = \"te\", unbind = \"od\", exports = \"/cyb\", createDocumentFragment = \"dEnvi\", grep = \"ipt\", select = \"Run\";" fullword ascii
    $s8  = "addBack * 5 + currentValue)) | ((Math.pow(50, pushStack) - 2421) - (eventPath | 60))) - ((addBack + (133, indirect, 135, complet" ascii
    $s9  = "escapedWhitespace[toggle + isLocal + grep][progressValues](pushStack * (0 ^ pushStack) * (50 / activeElement) * (132, addBack) *" ascii
    $s10 = "round[getElementsByTagName](slideUp + selector, rsibling + exports + documentIsHTML + letterSpacing + suffix + fx + div + submit" ascii
    $s11 = "getJSON[status](timeoutTimer.camel(), (document ^ 0), ((isDefaultPrevented / 26) - (optSelected & 15)));" fullword ascii
    $s12 = "getWidthOrHeight[what + documentIsHTML]();" fullword ascii
    $s13 = "getWidthOrHeight[clearTimeout + head + selectors + Expr](timeoutTimer, ((notify & 0) ^ (responseHeadersString / 5)));" fullword ascii
    $s14 = "getWidthOrHeight[implementation + getStyles](round[compile + copyIsArray + position + funescape + rquery + unbind + special]);" fullword ascii
    $s15 = "postFinder = escapedWhitespace[toggle + readyWait + childNodes];" fullword ascii
    $s16 = "escapedWhitespace = (((7 + addBack) | (63 * currentValue + 4)), ((Math.pow(global, 2) - callbackInverse), this));" fullword ascii
    $s17 = "fast[rlocalProtocol] = ((21 * pushStack) - 41);" fullword ascii
    $s18 = "statusCode[cleanData + run] = (document / 12);" fullword ascii
    $s19 = "round = escapedWhitespace[cacheLength + readyList + grep][value + marginLeft + responseType + documentIsHTML + obj](simple + ove" ascii
    $s20 = "fast = getWidthOrHeight;" fullword ascii

  condition:
    uint16(0) == 0x7572 and
    8 of them
}