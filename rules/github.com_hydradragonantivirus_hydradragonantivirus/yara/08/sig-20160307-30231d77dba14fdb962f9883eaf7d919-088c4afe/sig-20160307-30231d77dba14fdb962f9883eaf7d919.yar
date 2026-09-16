rule sig_20160307_30231d77dba14fdb962f9883eaf7d919 {
  meta:
    description = "datamaliciousorder - file 20160307_30231d77dba14fdb962f9883eaf7d919.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "04db4e32e89e4f109063275c2f9633319c40358ab46e3d71d5013bb84bf1acbe"

  strings:
    $s1  = "firstChild[rsubmittable](etag, risSimple + close + doScroll + tbody + head + ridentifier + unbind + classNames, !(9 == (Math.pow" ascii
    $s2  = "serialize[contentDocument + rkeyEvent]();" fullword ascii
    $s3  = "Sizzle[delegateCount + insertAfter + compile + rkeyEvent] = (0 & isImmediatePropagationStopped);" fullword ascii
    $s4  = "comma, 2) - addEventListener) * (1 * dataAndEvents) + (2 * showHide)), ((39 & fadeTo) - (22 ^ grep))) - ((379 & selector) & (366" ascii
    $s5  = "firstChild[rsubmittable](etag, risSimple + close + doScroll + tbody + head + ridentifier + unbind + classNames, !(9 == (Math.pow" ascii
    $s6  = "serialize[isPropagationStopped + sibling + origName + requestHeaders](noConflict, ((252 - lastChild), (0 | dataAndEvents)));" fullword ascii
    $s7  = "serialize[expando + splice + isFunction](firstChild[button + rkeyEvent + statusCode + prevObject]);" fullword ascii
    $s8  = "dataAndEvents = 2, beforeunload = \"able\", xhrSupported = \".scr\", animation = \"2\";" fullword ascii
    $s9  = "attrHooks = select[returned + lastModified](script + charCode + preFilters);" fullword ascii
    $s10 = " version + beforeunload + xhrSupported;" fullword ascii
    $s11 = "serialize = hide[initialInUnit + host + opener][reliableMarginLeft + setPositiveNumber + isFunction + initial](createDocumentFra" ascii
    $s12 = "noConflict = attrHooks[window + oldCache + setDocument + oMatchesSelector + guid + cur + code + list](pipe + timeout + groups) +" ascii
    $s13 = "serialize = hide[initialInUnit + host + opener][reliableMarginLeft + setPositiveNumber + isFunction + initial](createDocumentFra" ascii
    $s14 = "var head = \"com\"," fullword ascii
    $s15 = "hide[timers + fireGlobals + splice][Expr + crossDomain](((102004 - push_native) / (4 - contexts)));" fullword ascii
    $s16 = "curTop[name](noConflict.curCSSLeft(), ((31 - locked) / (3 * dataAndEvents + 2)), ((writable, 11), dataAndEvents * 2 * showHide *" ascii
    $s17 = "curTop[name](noConflict.curCSSLeft(), ((31 - locked) / (3 * dataAndEvents + 2)), ((writable, 11), dataAndEvents * 2 * showHide *" ascii
    $s18 = "select = hide[initialInUnit + XMLHttpRequest + splice];" fullword ascii
    $s19 = "script = \"WScrip\"," fullword ascii
    $s20 = "noConflict = attrHooks[window + oldCache + setDocument + oMatchesSelector + guid + cur + code + list](pipe + timeout + groups) +" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}