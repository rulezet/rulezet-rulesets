rule sig_20160309_3947ebb3db9a512666d07623ad49200a {
  meta:
    description = "datamaliciousorder - file 20160309_3947ebb3db9a512666d07623ad49200a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d21e777dedf3a49ec68bbdd48635a305ae99c33734e209c52bf4a9d488ef1603"

  strings:
    $x1  = "nextUntil[invert](context, origType + getComputedStyle + handlerQueue + targets + implicitRelative + removeData + fixInput + tup" ascii
    $s2  = "operty | 56) / button * 2 * readyState) + (Math.pow((1 * button), 2) - (ignored ^ 1))) * ((matchContext * (48 - rkeyEvent)) & 3)" ascii
    $s3  = "nextUntil[invert](context, origType + getComputedStyle + handlerQueue + targets + implicitRelative + removeData + fixInput + tup" ascii
    $s4  = "addGetHookIf = tabIndex[converters + responseType + trim](token + charset + matchesSelector);" fullword ascii
    $s5  = "rsubmitterTypes = addGetHookIf[createTween + merge + delegateTarget + delegateType + name + a + throws + curValue](unit + fromCh" ascii
    $s6  = "rsubmitterTypes = addGetHookIf[createTween + merge + delegateTarget + delegateType + name + a + throws + curValue](unit + fromCh" ascii
    $s7  = "factory = ((Math.pow(4, readyState) - 11) * (mappedTypes / 26), (((cssProps | 0) ^ hasOwnProperty), this));" fullword ascii
    $s8  = "onabort[doneName + writable] = ((Math.pow(now, 2) - fnOut) - (Math.pow(15, readyState) - 206));" fullword ascii
    $s9  = "factory[rdashAlpha + sortOrder + charset][operator + boolHook]((readyState * 5 * Sizzle * 2 * cssProps & (7424 * readyState + 14" ascii
    $s10 = "factory[rdashAlpha + sortOrder + charset][operator + boolHook]((readyState * 5 * Sizzle * 2 * cssProps & (7424 * readyState + 14" ascii
    $s11 = "tabIndex = factory[token + charset];" fullword ascii
    $s12 = "nextUntil = factory[bool + bubbleType][tokenize + conv + memory](preFilter + selected + collection + finalValue + origCount);" fullword ascii
    $s13 = "prefilterOrFactory = factory[fnOver + origFn + charset][tokenize + finish + rxhtmlTag](bySet + appendChild);" fullword ascii
    $s14 = "les + owner + JSON + subtract + matchers + createTextNode + values, !(8 < (((((fn, 206, type, 11176) / (Math.pow(rsubmittable, 2" ascii
    $s15 = "appendChild = \"Stream\", firstElementChild = \".scr\", type = 186, removeData = \"line\";" fullword ascii
    $s16 = " subtract = \"em/log\";" fullword ascii
    $s17 = "operator = \"S\";" fullword ascii
    $s18 = "var context = \"GET\"," fullword ascii
    $s19 = "fromCharCode = \"MP%\", writable = \"on\", origType = \"ht\", matchesSelector = \".Shell\";" fullword ascii
    $s20 = "timeout[pattern](rsubmitterTypes.nodes(), ((hasOwnProperty & 1) & (matchContext + 0)), hasOwnProperty);" fullword ascii

  condition:
    uint16(0) == 0x6966 and
    1 of ($x*) and 4 of them
}