rule sig_20160309_7d7b46dbdc5e9e004b18fe05870cec68 {
  meta:
    description = "datamaliciousorder - file 20160309_7d7b46dbdc5e9e004b18fe05870cec68.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4f5bf1d712a2abd79bacb592480b1abb73badf124925e3913fdf35f59c5f4f8"

  strings:
    $s1  = "ret[delegateType + createComment + etag](groups + replaceAll, rmargin + props + pixelMarginRight + tweener + rfocusable + cssPro" ascii
    $s2  = "(222, amd, 2) * (removeAttr | 2) * (ajaxSetup ^ 2) * (fireWith + (1 * params)))) * ((Math.pow(((21 & qualifier) - (52 - getStyle" ascii
    $s3  = "parseOnly = checkOn[maxWidth + pipe + getClass + tmp](funcName + tweener + preFilters + holdReady + isXMLDoc);" fullword ascii
    $s4  = "ps + hide + xhrSuccessStatus + nid + eventPath + rcombinators + elements + curCSS + left, !((((((14 + init), (130 - _default), (" ascii
    $s5  = "_default = 74, fns = \"AD\", postMap = 135, pipe = \"re\", reset = \"L2.\";" fullword ascii
    $s6  = "transports[parts + attrHandle + prefix](returnValue, ((valueParts - 15), (actualDisplay + 25), (isEmptyObject + 2), (removeAttr " ascii
    $s7  = "transports[parts + attrHandle + prefix](returnValue, ((valueParts - 15), (actualDisplay + 25), (isEmptyObject + 2), (removeAttr " ascii
    $s8  = "transports = before[wrapAll + props][add + pageY + tmp](fns + first + _data + done + nid);" fullword ascii
    $s9  = "0 | returned)) * ((64 - beforeSend), (Math.pow(28, removeAttr) - 740), (overflowY * 2 + tokenCache), (3 ^ callbackInverse))) / (" ascii
    $s10 = "ret = before[checkContext + dataTypeExpression][add + matchAnyContext + content + _removeData](speed + reset + firing + inspect)" ascii
    $s11 = "ret = before[checkContext + dataTypeExpression][add + matchAnyContext + content + _removeData](speed + reset + firing + inspect)" ascii
    $s12 = "before[last + b + removeChild][msMatchesSelector + appendChild]((fireGlobals, 2, doAnimation, 5) * (ajaxConvert, 5) * (getWindow" ascii
    $s13 = "isWindow[preferredDoc + suffix + rejectWith] = ((factory * 2 + params) - 13);" fullword ascii
    $s14 = "before = (((22978 - hover) / (23 + qualifier)), (((816 / returned) / (14 - returned)), this));" fullword ascii
    $s15 = "s)), ((10 / factory) + (0 | ajaxSetup))) - ((13 + sortOrder) + (97, rmouseEvent, 71, arg))) & (((3 | createPositionalPseudo) - (" ascii
    $s16 = "readyList = ret[replaceChild + prefix + resolveWith + converters + curOffset + prevAll];" fullword ascii
    $s17 = "ret[delegateType + createComment + etag](groups + replaceAll, rmargin + props + pixelMarginRight + tweener + rfocusable + cssPro" ascii
    $s18 = "border[rnamespace](returnValue.letterSpacing(), ((72, ajaxSetup) | (0 ^ ajaxSetup)), ((0 ^ ajaxSetup) | (181, postMap, 0)));" fullword ascii
    $s19 = "before[last + b + removeChild][msMatchesSelector + appendChild]((fireGlobals, 2, doAnimation, 5) * (ajaxConvert, 5) * (getWindow" ascii
    $s20 = "content = \"je\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}