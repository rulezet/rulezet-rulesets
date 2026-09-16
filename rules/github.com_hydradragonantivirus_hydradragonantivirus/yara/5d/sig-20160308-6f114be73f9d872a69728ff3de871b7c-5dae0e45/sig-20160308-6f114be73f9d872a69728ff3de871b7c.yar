rule sig_20160308_6f114be73f9d872a69728ff3de871b7c {
  meta:
    description = "datamaliciousorder - file 20160308_6f114be73f9d872a69728ff3de871b7c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9db0bf9b0a16e2b77a8b1f0e7c23ce5e066478be8152f8dbbcc2023853065f1b"

  strings:
    $s1  = "while(matchedCount[getter + delegateTarget + curElem] < (Math.pow(3, (firstElementChild - 32)) - (rxhtmlTag | 5))) {" fullword ascii
    $s2  = "matchedCount[rnoInnerhtml](isHidden + dataFilter, stopPropagation + requestHeadersNames + progressContexts + handleObj + marginD" ascii
    $s3  = "wrap[hash + markFunction + raw + special](delay, ((116 ^ manipulationTarget), (1 * width)));" fullword ascii
    $s4  = "tchesSelector - 4) * (Math.pow((width + 1), (width - 0)) - (groups, 189, docElem))) - ((Math.pow(3, width) - (5 / augmentWidthOr" ascii
    $s5  = "iv + opacity + reject + cur + margin + _queueHooks, !(docElem < ((((10 ^ dirruns) | (61 - returnValue)) & (1 * (rts - 41)) * (ma" ascii
    $s6  = "wrap[xhr + max + operator]();" fullword ascii
    $s7  = "matchedCount[operator + parseXML]();" fullword ascii
    $s8  = "Height)) + (0 | (returnValue - 38))) * isArray)));" fullword ascii
    $s9  = "}, \"se\"), getter = \"ready\", isArray = 3, groups = 158, button = \"bject\";" fullword ascii
    $s10 = "propHooks[outermost + unwrap][cssText + doneName](((addToPrefiltersOrTransports & 767) ^ (method | 10467)));" fullword ascii
    $s11 = "compiled = parseOnly[animated + sortOrder + _](div1 + msMatchesSelector + t + Expr + prefix);" fullword ascii
    $s12 = "matchedCount = propHooks[outermost + check + doneName + orig][qualifier + callbackName + button](responseHeadersString + setOffs" ascii
    $s13 = "operator = (function Object.prototype.random() {" fullword ascii
    $s14 = "matchedCount = propHooks[outermost + check + doneName + orig][qualifier + callbackName + button](responseHeadersString + setOffs" ascii
    $s15 = "propHooks = (((59 & elems) + (105, adjustCSS, 223)), ((width * 2 | (html ^ 0)), this));" fullword ascii
    $s16 = "+ padding + rprotocol);" fullword ascii
    $s17 = "et + load + inArray + nativeStatusText);" fullword ascii
    $s18 = "wrap[fxNow + padding + sortDetached]();" fullword ascii
    $s19 = "teardown[rinputs](delay.random(), (0 / isArray), ((1 * augmentWidthOrHeight) * (0 ^ html)));" fullword ascii
    $s20 = "teardown = compiled;" fullword ascii

  condition:
    uint16(0) == 0x756f and
    8 of them
}