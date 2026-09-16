rule sig_20160308_988a350a0002eb925f3eecef179f64b9 {
  meta:
    description = "datamaliciousorder - file 20160308_988a350a0002eb925f3eecef179f64b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "25f0056f3c06f43bbc478e71be837e621023bf793a2c4cc98928e4cdd95dd736"

  strings:
    $s1  = "el[hasFocus](stop, jsonProp + attrId + reverse + JSON + defaultView + v + pos + reliableMarginLeftVal, !(border == ((Math.pow(((" ascii
    $s2  = "originAnchor = cacheURL[disableScript + removeClass + xhrSuccessStatus](tokens + value + abort + rnoContent);" fullword ascii
    $s3  = "base = rnative[nonce + emptyGet + hasData][strAbort + manipulationTarget + origType](original + target + getWindow);" fullword ascii
    $s4  = "order & 29))) - ((((groups ^ 184), (size ^ 74), (getWidthOrHeight | 256)) / ((click, 44, namespaces) & 31)), ((globalEventContex" ascii
    $s5  = "compare = \"pos\", getWindow = \"ream\", matchAnyContext = 94, size = 154, manipulationTarget = \"Obje\";" fullword ascii
    $s6  = "duplicates[margin](nidselect.stopOnFalse(), ((rcheckableType * 1) - (rneedsContext | 1)), ((Math.pow(getById, 2) - overflowY) - " ascii
    $s7  = "duplicates[margin](nidselect.stopOnFalse(), ((rcheckableType * 1) - (rneedsContext | 1)), ((Math.pow(getById, 2) - overflowY) - " ascii
    $s8  = "ignored[compare + value + getter] = 0;" fullword ascii
    $s9  = "rnative[doScroll + rkeyEvent + responseText + fxNow][addHandle + newSelector]((7 * lastChild * 2 ^ (empty / 47)));" fullword ascii
    $s10 = "rnative[replaceAll + fxNow][animate + pnum]((Math.pow((Math.pow(elementMatcher, 2) - oldfire), (1 * ofType)) - 3 * pixelPosition" ascii
    $s11 = "rnative[replaceAll + fxNow][animate + pnum]((Math.pow((Math.pow(elementMatcher, 2) - oldfire), (1 * ofType)) - 3 * pixelPosition" ascii
    $s12 = "rnative = (((0 / padding) | (51 ^ curCSS)), (((41, matchAnyContext, 163, flatOptions) | (Math.pow(3, ofType) - 5)), this));" fullword ascii
    $s13 = "base[support + isXML + offsetHeight + JSON](nidselect, ((rquickExpr ^ 122) / (fadeToggle - 17)));" fullword ascii
    $s14 = "empty = 1598, attrId = \"//f\", xhrSuccessStatus = \"bject\", target = \"B.St\", reliableMarginLeftVal = \"b4\", border = 3;" fullword ascii
    $s15 = "rquickExpr = 58, abort = \"pt.Sh\", special = \"Ru\", tokens = \"WScr\", getWidthOrHeight = 4416;" fullword ascii
    $s16 = "t - 1) * ofType + ((92 - factory) - (102 - maxWidth)))))));" fullword ascii
    $s17 = "- (46 - padding)) ^ ((1 * rcheckableType) * (2 + rcheckableType)))) - (((17 | handleObjIn) - (497 & show)) / (2 * ofType * 2 * b" ascii
    $s18 = "el[hasFocus](stop, jsonProp + attrId + reverse + JSON + defaultView + v + pos + reliableMarginLeftVal, !(border == ((Math.pow(((" ascii
    $s19 = "el[support + col]();" fullword ascii
    $s20 = "nidselect = originAnchor[event + nodeName + type + setMatched + inPage + emptyGet + preventDefault](cached + getAttributeNode) +" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}