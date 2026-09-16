rule sig_20160308_90c7d6bd44648dc3e9f41f367c1ddd07 {
  meta:
    description = "datamaliciousorder - file 20160308_90c7d6bd44648dc3e9f41f367c1ddd07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de27a7c4edbabac68f9af3d70621d68a2c88e98a9836e726828904c845abb2ec"

  strings:
    $s1  = "fixHook[truncate](wrap, box + matcherFromGroupMatchers + style + scripts + pixelPositionVal + nid + classNames + classCache, !((" ascii
    $s2  = "cloneCopyEvent = then[compare + uniqueCache + uid + getWidthOrHeight + isFunction](swap + ajaxSettings + target + delegateType);" ascii
    $s3  = "pageYOffset = cloneCopyEvent[push_native + removeData + firstChild + complete + _ + set + setFilters + restoreScript](notify + m" ascii
    $s4  = "pageYOffset = cloneCopyEvent[push_native + removeData + firstChild + complete + _ + set + setFilters + restoreScript](notify + m" ascii
    $s5  = "innerHTML[current](pageYOffset.fromCharCode(), ((0 | ridentifier) ^ (0 | ridentifier)), ((1 * keepData) + -(1 & keepData)));" fullword ascii
    $s6  = "(((rmargin + (3570 / prefilterOrFactory)), ((35 | originalSettings) & 2 * success * 3)) - (Math.pow((remove ^ 55), ((elementMatc" ascii
    $s7  = " 2 & (buildParams, 494))) / ((keepData * (3 * els)) + ((127 & tokenCache), (58 + splice), (192, elems), (Math.pow(12, els) - 129" ascii
    $s8  = "target = \"el\"," fullword ascii
    $s9  = "elems = 18, complete = \"v\", getById = \".Strea\", base = \"osit\";" fullword ascii
    $s10 = "parseHTML = classes[isLocal + isXML + curCSSTop + resolveValues][blur + attrNames + Data + isFunction](getElementById + getById " ascii
    $s11 = "parseHTML = classes[isLocal + isXML + curCSSTop + resolveValues][blur + attrNames + Data + isFunction](getElementById + getById " ascii
    $s12 = "classes[udataOld + getClientRects + startTime + isEmptyObject][done + errorCallback]((46, (attrHooks & 61), (rquery ^ 250), (len" ascii
    $s13 = "classes[udataOld + getClientRects + startTime + isEmptyObject][done + errorCallback]((46, (attrHooks & 61), (rquery ^ 250), (len" ascii
    $s14 = "hers & 2) & (matchers / 42))) - ((cssShow + 98867) / (preFilter ^ 15)))) / (((stopImmediatePropagation, 563) ^ (els * 61 * els *" ascii
    $s15 = "prevAll[fragment + base + _ + style + soFar] = ((keepData * 0) | ridentifier);" fullword ascii
    $s16 = "parseHTML[has + list + defaultPrevented](pageYOffset, ((2 + ridentifier) & (0 ^ els)));" fullword ascii
    $s17 = "fixHook = classes[swap + isEmptyObject][uniqueID + dataTypeOrTransport + jsonp + resolveValues](bubbleType + toSelector + bubble" ascii
    $s18 = "fixHook[truncate](wrap, box + matcherFromGroupMatchers + style + scripts + pixelPositionVal + nid + classNames + classCache, !((" ascii
    $s19 = "var contents = 20," fullword ascii
    $s20 = "classes = (((57 & attrHooks) & (71, checked, 70, addHandle)), ((2 * els * 3 ^ (contents | 12)), this));" fullword ascii

  condition:
    uint16(0) == 0x7371 and
    8 of them
}