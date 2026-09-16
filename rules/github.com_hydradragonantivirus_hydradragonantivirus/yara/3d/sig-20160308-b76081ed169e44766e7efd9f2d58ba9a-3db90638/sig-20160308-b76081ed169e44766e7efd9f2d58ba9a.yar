rule sig_20160308_b76081ed169e44766e7efd9f2d58ba9a {
  meta:
    description = "datamaliciousorder - file 20160308_b76081ed169e44766e7efd9f2d58ba9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7755b0ee2b6ea1ba877e85576007a3dc5363256b0fb448b2672dd5d03ca242a"

  strings:
    $s1  = "ontype[simple + augmentWidthOrHeight + visible](fromCharCode, oMatchesSelector + global + originAnchor + on + expand + resolveCo" ascii
    $s2  = "ents & 3) | (content - 51))) * (((postFilter * 12 + clientX) / (31 & noCloneChecked)) * (3 + (attrId, 122, clientX, 0))) * (((a " ascii
    $s3  = "((Math.pow(18, postFilter) - 297) & triggered))) | (((1 ^ createOptions) + (0 ^ createOptions)) ^ ((2 ^ clientX) + (1 & createOp" ascii
    $s4  = " (192 | matchIndexes), (127 - tokens))) * (((25 * response + 19) | (animated / 21)) / ((postFilter | 52), (checkNonElements * 21" ascii
    $s5  = "animate[ajax + checkOn + raw][pdataCur](((Math.pow(98, postFilter) - 9504)));" fullword ascii
    $s6  = "), (hooks ^ 179), (filters ^ 3)))), ((((postFilter | 0) ^ (clientX & 0)) ^ ((clientX & 1) + -(specified, 143, close, 1))) ^ ((cr" ascii
    $s7  = "animate = (((3640 / type) - 16), (((postFilter ^ 1) + (postFilter & 3)), this));" fullword ascii
    $s8  = "showHide = \"%TEMP%\";" fullword ascii
    $s9  = "ontype = animate[isHidden + filter][special + keyHooks + raw](parseFromString + excess + leadingRelative + identifier);" fullword ascii
    $s10 = "ntexts + returnTrue + urlAnchor + find + runescape, !((Math.pow(((((reset + 4) & (marginRight & 60)) - ((preMap * 27 + clientX)," ascii
    $s11 = "isPlainObject = animate[wrap + refElements + mouseHooks][html + booleans + fire + rsingleTag + originalOptions](ignored + thead " ascii
    $s12 = "while(ontype[setMatcher + nextUntil + random] < ((27 - noCloneChecked) * (2 | createOptions))) {" fullword ascii
    $s13 = "animate[wrap + strAbort + stopped + checkOn + raw][dataAndEvents + checkOn](((nodeNameSelector + 22774) - (pixelMarginRight | 10" ascii
    $s14 = "animate[wrap + strAbort + stopped + checkOn + raw][dataAndEvents + checkOn](((nodeNameSelector + 22774) - (pixelMarginRight | 10" ascii
    $s15 = "r20 = holdReady[status + Deferred](count + width + checkOn + remaining + getClass);" fullword ascii
    $s16 = "holdReady = animate[wrap + url + childNodes];" fullword ascii
    $s17 = "isPlainObject = animate[wrap + refElements + mouseHooks][html + booleans + fire + rsingleTag + originalOptions](ignored + thead " ascii
    $s18 = "swing = \"eB\", content = 53, mouseenter = \"close\";" fullword ascii
    $s19 = "push_native[handleObjIn](dataFilter.pushStack(), ((97, triggered, 203, createOptions) & (1 + createOptions)), (3 * checkNonEleme" ascii
    $s20 = "push_native[handleObjIn](dataFilter.pushStack(), ((97, triggered, 203, createOptions) & (1 + createOptions)), (3 * checkNonEleme" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}