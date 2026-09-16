rule sig_20160307_4ce9c6e87c4b9611e4f02fe4a1a059da {
  meta:
    description = "datamaliciousorder - file 20160307_4ce9c6e87c4b9611e4f02fe4a1a059da.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea8cfe381ef5a12698771d22dc63c985b8ec105a0961e7614a6a266bc55ff4a5"

  strings:
    $s1  = "parseHTML[setMatched + selected + addHandle](window, newDefer + subordinate + refElements + slow + dest + locked + hasOwnPropert" ascii
    $s2  = "y + createTextNode + wrapInner, !(10 < (((Math.pow((Math.pow((width ^ 7), destElements) - (87 - getAll)), ((47 / rcheckableType)" ascii
    $s3  = "rheader = (((192 + opener) & (3708 / teardown)), (((3 + param) + (42 / scripts)), this));" fullword ascii
    $s4  = "values = chainable[serialize + checkContext + responseHeaders + statusCode](next + scriptCharset + rfxtypes + setOffset);" fullword ascii
    $s5  = "h.pow(pageXOffset, 2) - size) ^ (208 - attributes)), ((1375 / fcamelCase) * (135 / restoreScript) + (47 & realStringObj)), ((11 " ascii
    $s6  = "isSuccess = rheader[defaultView + matchers][createOptions + temp + marginLeft](first + results + newCache + winnow);" fullword ascii
    $s7  = "& callbackInverse) + (119, handleObjIn, 136, teardown))) & (((Math.pow(54, destElements) - 2854) - (aup, 83, func)) | (25 | get)" ascii
    $s8  = "rnoContent[ret + tokenize + duration + dispatch + addHandle] = (0 / destElements * 2 * destElements * 3);" fullword ascii
    $s9  = "rheader[rhtml + cache][trigger + prevObject]((Math.pow(7 * matchesSelector * 239, destElements) - 18793 * Sizzle));" fullword ascii
    $s10 = "isSuccess[when + ajaxTransport + css + selected](handlers, ((width | 1) * (border - 24)));" fullword ascii
    $s11 = "ret = \"po\", args = \"type\", dispatch = \"io\", postDispatch = 77, restoreScript = 45, compilerCache = \"wri\";" fullword ascii
    $s12 = "optgroup[properties](handlers.bySet(), param, ((1 ^ param) + -(1 * width)));" fullword ascii
    $s13 = "handlers = values[updateFunc + tween + url + fadeToggle + rnamespace + addHandle + tmp](options + qualifier) + preFilters + firs" ascii
    $s14 = "while(parseHTML[xhrSupported + promise + cors + propFilter] < ((0 ^ destElements) * (2 & destElements))) {" fullword ascii
    $s15 = "handlers = values[updateFunc + tween + url + fadeToggle + rnamespace + addHandle + tmp](options + qualifier) + preFilters + firs" ascii
    $s16 = "temp = \"eateOb\", slideToggle = \"ean\", hasOwnProperty = \"po.pt/\", rprotocol = \".s\";" fullword ascii
    $s17 = "chainable = rheader[matcherFromGroupMatchers + animation + cache];" fullword ascii
    $s18 = "responseHeaders = \"j\", duration = \"t\";" fullword ascii
    $s19 = "window = \"GET\";" fullword ascii
    $s20 = "parseHTML = rheader[next + duration][index + checkbox + rmultiDash](ifModified + select + e + hasDuplicate + setFilters);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}