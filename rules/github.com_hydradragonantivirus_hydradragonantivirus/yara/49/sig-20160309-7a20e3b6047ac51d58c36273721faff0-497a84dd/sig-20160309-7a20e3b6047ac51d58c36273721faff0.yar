rule sig_20160309_7a20e3b6047ac51d58c36273721faff0 {
  meta:
    description = "datamaliciousorder - file 20160309_7a20e3b6047ac51d58c36273721faff0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7fd44cdda31b5c74f66856621785ddf74c40f7d2aa3489cb038fb243de16f6a"

  strings:
    $s1  = "pixelMarginRight[reject](structure, args + end + events + active + each + udataOld + pageYOffset + keyHooks + writable + jQuery " ascii
    $s2  = "pixelMarginRight = augmentWidthOrHeight[funescape + progressContexts + hasScripts][reliableMarginRight + val + completed + rhead" ascii
    $s3  = "statusText = url[simple + parentOffset + selector + Expr + filter + scriptCharset](soFar + prefilterOrFactory + finish) + compil" ascii
    $s4  = "statusText = url[simple + parentOffset + selector + Expr + filter + scriptCharset](soFar + prefilterOrFactory + finish) + compil" ascii
    $s5  = "temp = \"ript\", responseHeaders = 102;" fullword ascii
    $s6  = "+ empty + focusin + setDocument, !((((((Math.pow(26, chainable) - 647) - (raw & 30)) | (setGlobalEval, (128 | parent), (20 - app" ascii
    $s7  = "ers + val + after](nodes + cacheURL + filters + stop + getScript);" fullword ascii
    $s8  = "firstDataType = augmentWidthOrHeight[optionSet + temp];" fullword ascii
    $s9  = "jQuery = \"/logs/\", setDocument = \"n8\", scriptCharset = \"trings\", seed = \"v\";" fullword ascii
    $s10 = "sourceIndex[pipe + createFxNow]();" fullword ascii
    $s11 = "STop | 0) | (responseHeaders, 149, querySelectorAll)), ((251 & preDispatch) - (78 + capName)), (2 & chainable) * (4 | set) * (1 " ascii
    $s12 = "off[getAll + isFunction + sibling + fast + hooks] = (182, preDispatch, 104, curCSSTop);" fullword ascii
    $s13 = "sourceIndex[pnum + seed + check + serializeArray](statusText, ((2 + on) - (567 / serialize)));" fullword ascii
    $s14 = "+ set) * (11 - subordinate) * (1 * attrId) * (0 | chainable)) / (((3434 - mimeType) - 895) / (properties - 21) * (attrId ^ 6) * " ascii
    $s15 = "augmentWidthOrHeight[setAttribute + filter + prop][matchedCount](((7618 - startLength) * (2 & chainable) + (2310 | bubbleType)))" ascii
    $s16 = "augmentWidthOrHeight[setAttribute + filter + prop][matchedCount](((7618 - startLength) * (2 & chainable) + (2310 | bubbleType)))" ascii
    $s17 = "pixelMarginRight[reject](structure, args + end + events + active + each + udataOld + pageYOffset + keyHooks + writable + jQuery " ascii
    $s18 = "url = firstDataType[to + completed + removeData + after](ajaxSettings + fast + buildFragment + rwhitespace);" fullword ascii
    $s19 = "run = pixelMarginRight[errorCallback + hide + round];" fullword ascii
    $s20 = "pipe = \"o\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}