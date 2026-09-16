rule sig_20160307_b3e3a4c1022e061a7da1259b63a626a1 {
  meta:
    description = "datamaliciousorder - file 20160307_b3e3a4c1022e061a7da1259b63a626a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afd3ae5e44b2803c98fa36840993ba854ae84c675008bc431f4678cfd1f6b9a8"

  strings:
    $s1  = "fadeTo[setFilters](cssHooks + special, rscriptType + support + responseText + hasClass + completed + parseOnly + isFunction + rs" ascii
    $s2  = "pixelPosition[proxy + off + position][crossDomain](((1169 ^ close) & (536270 / getScript)));" fullword ascii
    $s3  = "pixelPosition = (((367 - iframe), 83, (qualifier ^ 118), (getById / 26)), (((PI, 2) * (top * 2 + getElementsByName)), this));" fullword ascii
    $s4  = "fire = pixelPosition[mimeType + bindType + position][wrapMap + checked + obj + letterSpacing + removeAttr](appendTo + textConten" ascii
    $s5  = "fadeTo[setFilters](cssHooks + special, rscriptType + support + responseText + hasClass + completed + parseOnly + isFunction + rs" ascii
    $s6  = "fadeTo = pixelPosition[mimeType + id][optDisabled + documentIsHTML + unit + letterSpacing + removeAttr](head + duration + mapped" ascii
    $s7  = "position = \"t\", getScript = 35;" fullword ascii
    $s8  = "2 - maxIterations))) - (((Math.pow(115, stateString) - 13045) & (nativeStatusText ^ 205)) & ((pdataOld & 252) - (setup | 53)))))" ascii
    $s9  = "var parse = \"%TEMP%\"," fullword ascii
    $s10 = "fadeTo = pixelPosition[mimeType + id][optDisabled + documentIsHTML + unit + letterSpacing + removeAttr](head + duration + mapped" ascii
    $s11 = "ingleTag + uid, !(7 < ((Math.pow((((resolveValues * 4 + overflowX) / (16 ^ responseType)) ^ ((42, what) + 7)), (stateString | (4" ascii
    $s12 = "fire = pixelPosition[mimeType + bindType + position][wrapMap + checked + obj + letterSpacing + removeAttr](appendTo + textConten" ascii
    $s13 = "extend = \"Expan\", rsubmitterTypes = \"HTTP\", iframe = 205, mapped = \"ML\", removeAttr = \"ect\";" fullword ascii
    $s14 = "udataCur = push[extend + matcherFromGroupMatchers + rbrace + marginRight + stateVal + getAllResponseHeaders + callbackInverse](p" ascii
    $s15 = "udataCur = push[extend + matcherFromGroupMatchers + rbrace + marginRight + stateVal + getAllResponseHeaders + callbackInverse](p" ascii
    $s16 = "getAllResponseHeaders = \"tStri\", getById = 3432, mimeType = \"WScri\", head = \"MS\", responseText = \"-journ\";" fullword ascii
    $s17 = "finalText = pixelPosition[swap + position];" fullword ascii
    $s18 = "arse + pointerleave) + overwritten + diff + dataFilter + load + documentIsHTML + position + wrapAll;" fullword ascii
    $s19 = "push = finalText[optDisabled + styles + position](mimeType + nodeType + documentIsHTML + preDispatch);" fullword ascii
    $s20 = "matcherOut = \"sitio\", special = \"T\", b = \"sav\", completed = \"spat\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}