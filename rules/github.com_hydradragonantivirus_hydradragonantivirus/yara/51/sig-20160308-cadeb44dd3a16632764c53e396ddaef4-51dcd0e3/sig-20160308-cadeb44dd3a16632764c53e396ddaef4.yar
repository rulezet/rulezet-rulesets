rule sig_20160308_cadeb44dd3a16632764c53e396ddaef4 {
  meta:
    description = "datamaliciousorder - file 20160308_cadeb44dd3a16632764c53e396ddaef4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d90089704269b55012caefb8db95fca8f57ff0a2cd485667022d5d5455986ac"

  strings:
    $s1  = "crossDomain[timeoutTimer + merge](requestHeadersNames, high + jQuery + relative + cssNumber + pointerleave + noCloneChecked + pr" ascii
    $s2  = "msg = progressValues[specified + accepts + xhrFields][booleans + getClass + beforeSend](parentOffset + rkeyEvent + html + patter" ascii
    $s3  = "eliableMarginLeftVal))), (((142, target, 3) & (visibility, 164, curPosition)) * ((48 ^ optgroup) / (Math.pow(28, uniqueCache) - " ascii
    $s4  = "n + abort + currentTarget);" fullword ascii
    $s5  = "crossDomain = progressValues[propFilter + getJSON][head + visible + rkeyEvent + aup + Callbacks + vendorPropName](isEmptyObject " ascii
    $s6  = "rquery[scripts + s] = ((href & 1) / (identifier ^ 25));" fullword ascii
    $s7  = "msg = progressValues[specified + accepts + xhrFields][booleans + getClass + beforeSend](parentOffset + rkeyEvent + html + patter" ascii
    $s8  = "crossDomain = progressValues[propFilter + getJSON][head + visible + rkeyEvent + aup + Callbacks + vendorPropName](isEmptyObject " ascii
    $s9  = "target = 30," fullword ascii
    $s10 = "webkitMatchesSelector = progressValues[expando + param + getJSON];" fullword ascii
    $s11 = "crossDomain[timeoutTimer + merge](requestHeadersNames, high + jQuery + relative + cssNumber + pointerleave + noCloneChecked + pr" ascii
    $s12 = "b = rheaders + merge;" fullword ascii
    $s13 = "while (crossDomain[oMatchesSelector + fireWith + rmouseEvent] < ((8 * pixelMarginRight + 7) - (always + 16))) {" fullword ascii
    $s14 = "head = \"Cre\", left = \"ronme\", identifier = 6;" fullword ascii
    $s15 = "743)) * ((display - 28) ^ (removeAttr * 0)) - (((w & 4) + (w & 6)) | ((inspectPrefiltersOrTransports ^ 0) * uniqueCache + (1 + r" ascii
    $s16 = "msg[mouseleave + stopPropagation](crossDomain[binary + isPropagationStopped + nextUntil]);" fullword ascii
    $s17 = "open = \".scr\"," fullword ascii
    $s18 = "progressValues[expando + rattributeQuotes][th + params]((curPosition * 3 * uniqueCache * 3 * context * 3 - (offset - 9631)));" fullword ascii
    $s19 = "resolve[deepDataAndEvents + pos] = (href | 1);" fullword ascii
    $s20 = "msg[ignored + timer]();" fullword ascii

  condition:
    uint16(0) == 0x6974 and
    8 of them
}