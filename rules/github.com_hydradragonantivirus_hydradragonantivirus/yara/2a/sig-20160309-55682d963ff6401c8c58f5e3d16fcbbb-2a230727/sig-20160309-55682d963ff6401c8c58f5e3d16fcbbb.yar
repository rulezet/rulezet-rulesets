rule sig_20160309_55682d963ff6401c8c58f5e3d16fcbbb {
  meta:
    description = "datamaliciousorder - file 20160309_55682d963ff6401c8c58f5e3d16fcbbb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ee680e81de8e995c425ecb2c994428bc430dc9cf9b5d4a05331f7a8663a23af"

  strings:
    $s1  = "_$[related + key][setPositiveNumber + postMap](((valueIsBorderBox - 3288) * (proxy ^ 0) + (apply + 367)));" fullword ascii
    $s2  = "deep[curElem + hold](add + pop, matches + fix + round + cacheLength + trim + responses + queue + width, !((((((0 | results) * (4" ascii
    $s3  = ", (49 - overrideMimeType) * (35 - show) * (8 * gotoEnd + 5), (fireGlobals ^ (2 + fireGlobals))) + (((41, ajaxSettings, 3) | (fir" ascii
    $s4  = "margin[curValue](addCombinator.funcName(), (results + -(30 - a)), (1 * fireGlobals));" fullword ascii
    $s5  = "4, responseContainer, 230, proxy)) * ((1 + fireGlobals) + (1 * results)))) * (((2 + readyList) * (1 * gotoEnd) + (6 & relative))" ascii
    $s6  = "deep = _$[actualDisplay + contentType][args + set + hasData + parse](startLength + getElementsByClassName + each + msFullscreenE" ascii
    $s7  = "deep = _$[actualDisplay + contentType][args + set + hasData + parse](startLength + getElementsByClassName + each + msFullscreenE" ascii
    $s8  = "eGlobals | 1)) & ((results * 1) + (proxy & 3)))) > compare));" fullword ascii
    $s9  = "overrideMimeType = 47, async = \"s\", proxy = 2;" fullword ascii
    $s10 = "open[key + amd] = (1 + fireGlobals);" fullword ascii
    $s11 = "class2type = \"WScr\", createDocumentFragment = \"Object\", dataPriv = \"eam\", val = \"%TEMP%\", pageY = \"Str\", e = \"v\";" fullword ascii
    $s12 = "special[arg + replaceChild + checkDisplay] = (0 & (results | 0));" fullword ascii
    $s13 = "window[elems + diff]();" fullword ascii
    $s14 = "parts[risSimple + ifModified + m](define);" fullword ascii
    $s15 = "fast = _$[firstElementChild + p];" fullword ascii
    $s16 = "lement + percent + dataShow);" fullword ascii
    $s17 = "addCombinator = fixInput[origFn + expanded + html + e + callbackInverse + checkNonElements + originalEvent + elementMatchers + u" ascii
    $s18 = "_$ = (((4 ^ fireGlobals), (98 ^ siblings)), (((0 | proxy) | (4 & relative)), this));" fullword ascii
    $s19 = "compare = 5;" fullword ascii
    $s20 = "parts = _$[class2type + responseText + p][event + node + key + diff + set + rxhtmlTag + key](prepend + pageY + dataPriv);" fullword ascii

  condition:
    uint16(0) == 0x7468 and
    8 of them
}