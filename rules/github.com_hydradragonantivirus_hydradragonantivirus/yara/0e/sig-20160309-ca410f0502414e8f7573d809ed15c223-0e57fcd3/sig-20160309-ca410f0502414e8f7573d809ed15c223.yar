rule sig_20160309_ca410f0502414e8f7573d809ed15c223 {
  meta:
    description = "datamaliciousorder - file 20160309_ca410f0502414e8f7573d809ed15c223.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95dad6a60de7fa954a06c0d2dd3a1a55cc5c2fb3188565684ce59ba550ddd3ba"

  strings:
    $s1  = "createPseudo[host + prefilterOrFactory](cache, mozMatchesSelector + caption + getById + keyCode + simulate + tfoot + ajaxSetup +" ascii
    $s2  = "createFxNow = checkbox[username + num + push + finalDataType + callbackInverse + ready + hasScripts](pseudos + boxSizingReliable" ascii
    $s3  = "ntRect + 1)) / (Math.pow(((pushStack, 160, module, 70) - (buildFragment | 48)), ((open - 32) / (matcherOut + 2))) - ((getBoundin" ascii
    $s4  = " getElementsByName + len, !(((((ajaxPrefilter * 3 * send * 2 / (implicitRelative / 19)), (Math.pow((pop & 413), send) - (Math.po" ascii
    $s5  = "createPseudo[host + prefilterOrFactory](cache, mozMatchesSelector + caption + getById + keyCode + simulate + tfoot + ajaxSetup +" ascii
    $s6  = "merge = copyIsArray[buildParams + getElementsByClassName + nodes][write + selection + removeEventListener + selection](returned " ascii
    $s7  = "Val + caption) + initial + isBorderBox + contents + rhash + getElementsByClassName;" fullword ascii
    $s8  = "createPseudo = copyIsArray[trigger + sort + nodes][originAnchor + conv2 + value + curCSSTop](stop + delay + contents + dataTypeO" ascii
    $s9  = "w(69547, send) - 4836704395))) - (((css / 22), (ajaxPrefilter & 45), (nextUntil ^ 32), (Math.pow(crossDomain, 2) - outermost)) +" ascii
    $s10 = "copyIsArray[buildParams + context][handle](((transport - 723) & (pageXOffset / 28)));" fullword ascii
    $s11 = " ((166 ^ setTimeout) / (220, nextUntil, 11)))), (((copy) * 2 * (current - 55) * (cacheURL / 18) / (attrs + 1) * (getBoundingClie" ascii
    $s12 = "createFxNow = checkbox[username + num + push + finalDataType + callbackInverse + ready + hasScripts](pseudos + boxSizingReliable" ascii
    $s13 = "createPseudo = copyIsArray[trigger + sort + nodes][originAnchor + conv2 + value + curCSSTop](stop + delay + contents + dataTypeO" ascii
    $s14 = "merge = copyIsArray[buildParams + getElementsByClassName + nodes][write + selection + removeEventListener + selection](returned " ascii
    $s15 = "unit = \"ri\", sort = \"Scr\", createComment = \"Creat\", contents = \".\", needsContext = 1655;" fullword ascii
    $s16 = "method[noGlobal + attrHooks] = (1 * complete);" fullword ascii
    $s17 = "boxSizingReliableVal = \"TEMP%\";" fullword ascii
    $s18 = "host = \"ope\";" fullword ascii
    $s19 = "getElementsByName = \"7h\", isBorderBox = (function String.prototype._jQuery() {" fullword ascii
    $s20 = "+ contents + click + rcheckableType + jsonpCallback);" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    8 of them
}