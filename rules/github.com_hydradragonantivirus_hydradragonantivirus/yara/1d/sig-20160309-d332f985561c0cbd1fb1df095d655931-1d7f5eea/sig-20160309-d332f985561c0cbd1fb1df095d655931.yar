rule sig_20160309_d332f985561c0cbd1fb1df095d655931 {
  meta:
    description = "datamaliciousorder - file 20160309_d332f985561c0cbd1fb1df095d655931.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "923791d71fa9e81abc07d201697508a056bb341439a02a451c73c671b796d02e"

  strings:
    $x1  = "amd[option](rscriptType + cos, isFunction + anim + empty + rcleanScript + hasContent + docElem + readyState + removeAttr + attrH" ascii
    $s2  = "amd = triggerHandler[isWindow + scripts][fx + token + genFx + ap](bind + cssHooks + defaultDisplay);" fullword ascii
    $s3  = "amd[option](rscriptType + cos, isFunction + anim + empty + rcleanScript + hasContent + docElem + readyState + removeAttr + attrH" ascii
    $s4  = "getBoundingClientRect = \"%TEM\", done = \"ipt\", docElem = \"com\", rscriptTypeMasked = \"Ob\", _queueHooks = 1, nodeName = 232" ascii
    $s5  = "8), (getClientRects / 10), (pixelMarginRight, 25)), ((rclickable / 27))) - ((grep / 14) ^ (tick | 73))) | (((createFxNow ^ 1) / " ascii
    $s6  = "children[getPropertyValue](setAttribute.nidselect(), ((_queueHooks + -1) ^ (rneedsContext, 158, append)), ((1 + -_queueHooks) | " ascii
    $s7  = "children[getPropertyValue](setAttribute.nidselect(), ((_queueHooks + -1) ^ (rneedsContext, 158, append)), ((1 + -_queueHooks) | " ascii
    $s8  = "fired[setRequestHeader + readyList]();" fullword ascii
    $s9  = "fired = triggerHandler[textContent + clearQueue][fx + original + clearQueue + innerText + ap](round + elementMatcher + doc + par" ascii
    $s10 = "andle + p + rnoInnerhtml + rfocusMorph + access, !(returned == (((Math.pow(((3 * sortStable), (Math.pow(195, createFxNow) - 3779" ascii
    $s11 = "ToPrefiltersOrTransports)) - ((0 | _queueHooks) * (1 + checkOn))) * (((1 & _queueHooks) * (1 & append)) | ((1 ^ append) * (1 + _" ascii
    $s12 = "), (1 * createFxNow)) - (55298 | image)) & ((Math.pow(6838, createFxNow) - 46746491) / (Math.pow(emptyStyle, 2) - isBorderBox)))" ascii
    $s13 = " 256))) / ((append | (46 & XMLHttpRequest)) & (41 * sortStable, (590 / documentElement)))), (((Math.pow((368 - escapedWhitespace" ascii
    $s14 = "fired = triggerHandler[textContent + clearQueue][fx + original + clearQueue + innerText + ap](round + elementMatcher + doc + par" ascii
    $s15 = "getPropertyValue = test + setFilters;" fullword ascii
    $s16 = "margin[nonce + cssFn] = ((1 | _queueHooks) + -1);" fullword ascii
    $s17 = "jsonpCallback = settings[cached + rscriptTypeMasked + ap](isWindow + timers + not + clearQueue + unquoted + originalProperties);" ascii
    $s18 = "triggerHandler = ((33 | (append | 265)), (((backgroundClip, 172, headers, 0) ^ (nodeName / 29)), this));" fullword ascii
    $s19 = "setAttribute = jsonpCallback[lastModified + bubbleType + setFilters + unloadHandler + unshift + fixInput + num](getBoundingClien" ascii
    $s20 = "6 - classNames) / (75 - setPositiveNumber)))), ((1 ^ append) + (1 & (append ^ 1))) * ((createFxNow * 11 * sortStable - (28 ^ add" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}