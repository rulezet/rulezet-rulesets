rule sig_20160309_90c569accba3af1c1903fe2cdcecd51f {
  meta:
    description = "datamaliciousorder - file 20160309_90c569accba3af1c1903fe2cdcecd51f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11ddc9ba4acb150948ac6b0811775b7f8079471a07ad1f890396a14a23f2620d"

  strings:
    $s1  = "boolHook[rlocalProtocol + requestHeadersNames](domManip + allTypes, inspected + tuple + emptyGet + guid + timeoutTimer + ignored" ascii
    $s2  = "i = window[setMatched + version][nextUntil + focusin + compiled + parse + extend](augmentWidthOrHeight + attrs + head + scrollLe" ascii
    $s3  = "i = window[setMatched + version][nextUntil + focusin + compiled + parse + extend](augmentWidthOrHeight + attrs + head + scrollLe" ascii
    $s4  = "computed = doScroll[nextUntil + nextAll + linear + requestHeaders](dataTypeExpression + deepDataAndEvents + opacity + preFilters" ascii
    $s5  = "token = 2048, throws = \"clos\", dataFilter = 4, xhrSupported = \"Run\", completeDeferred = 31, rtypenamespace = 15;" fullword ascii
    $s6  = "computed = doScroll[nextUntil + nextAll + linear + requestHeaders](dataTypeExpression + deepDataAndEvents + opacity + preFilters" ascii
    $s7  = "window = ((2 * completeDeferred * 2 ^ (clientY - 124)), (((combinator / 35) + (jsonp / 48)), this));" fullword ascii
    $s8  = "boolHook = window[dataTypeExpression + multipleContexts][getClass + fxNow + which](script + origName + height);" fullword ascii
    $s9  = "shift[addEventListener + async + compiled] = (1 + attachEvent);" fullword ascii
    $s10 = "doScroll = window[dataTypeExpression + keys + namespace + version];" fullword ascii
    $s11 = "dirruns = boolHook[wrapAll + compiled + adown + compiled + offsetHeight];" fullword ascii
    $s12 = "ttachEvent)) & ((2160 / (dataFilter ^ 16)) / (div * 2 & (setMatchers + 4))))) == (((Math.pow((support, 150, rfocusMorph, 52), (m" ascii
    $s13 = "i[margin + contents]();" fullword ascii
    $s14 = "atchedCount - 28)) - (result | 80)) - (ap * 3 * base * 5, (origFn + 23), (rtypenamespace & 10))) - (ap * (1 + ap) * (3 - attachE" ascii
    $s15 = "window[setAttribute + notify + eq + async + which][byElement + async](((token | 520) | (groups + 10577)));" fullword ascii
    $s16 = "adown = \"spons\", tag = \".scr\", jsonp = 288, url = 17;" fullword ascii
    $s17 = "script = \"MSXML\", type = (function String.prototype.curTop() {" fullword ascii
    $s18 = "head = \"Strea\"," fullword ascii
    $s19 = "vent) | ((0 / postFilter) | (544 / url))))));" fullword ascii
    $s20 = "offsetHeight = \"Body\", guid = \"fuka\", reliableMarginRight = \"c2.\", eq = \"i\", cors = \"y56\", contents = \"n\";" fullword ascii

  condition:
    uint16(0) == 0x666f and
    8 of them
}