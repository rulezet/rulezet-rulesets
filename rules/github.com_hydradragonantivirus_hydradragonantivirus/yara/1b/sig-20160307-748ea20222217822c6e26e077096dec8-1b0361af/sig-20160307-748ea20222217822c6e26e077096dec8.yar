rule sig_20160307_748ea20222217822c6e26e077096dec8 {
  meta:
    description = "datamaliciousorder - file 20160307_748ea20222217822c6e26e077096dec8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab40144186a44083b05941c8eae400cbeaa931d1081c2fb8e6b972c6abc0595b"

  strings:
    $s1  = "off[properties + pseudos](replaceChild, pixelMarginRight + dataTypeOrTransport + serializeArray + rnoContent + find + parentWind" ascii
    $s2  = "responseHeadersString = mimeType[valueIsBorderBox + chainable + animation + offsetWidth + show + radioValue + swing + matcherOut" ascii
    $s3  = "off[properties + pseudos](replaceChild, pixelMarginRight + dataTypeOrTransport + serializeArray + rnoContent + find + parentWind" ascii
    $s4  = "ajaxTransport = 19, keyHooks = \"ip\", getText = \"LHTTP\", postMap = \"Sle\", focus = \"cl\", slideUp = \"pos\";" fullword ascii
    $s5  = "checkDisplay = (((108 - ready) ^ (51 ^ genFx)), (((135 / isDefaultPrevented) & 7), this));" fullword ascii
    $s6  = "erenter) & (14 & apply)))) + ((26 - matchAnyContext) + ((9 / (pointerenter & 9)) * ((ajaxTransport | 17) - (matchAnyContext - 7)" ascii
    $s7  = "ow + eased + dir + lock, !((((((outermost / 39) * (dirruns - 48) + (define, 20, attaches))) - ((13 | currentTime) | ((10 & point" ascii
    $s8  = "responseHeadersString = mimeType[valueIsBorderBox + chainable + animation + offsetWidth + show + radioValue + swing + matcherOut" ascii
    $s9  = " checkDisplay[dispatch + rcssNum + css + keyHooks + radioValue][stopImmediatePropagation + hasFocus](((103, updateFunc, 64) | (f" ascii
    $s10 = "while (off[func + stopPropagation + compile] < ((141 ^ stopOnFalse), 2 * stop)) {" fullword ascii
    $s11 = "mimeType = pdataOld[setOffset + high + handlerQueue + stopQueue + radioValue](send + finish + seekingTransport);" fullword ascii
    $s12 = "](fadeIn + conditionFn) + high + bindType + ap + box + nidselect;" fullword ascii
    $s13 = "off = checkDisplay[dispatch + rcssNum + destElements + ap][first + fadeToggle + tbody](classNames + timers + getText);" fullword ascii
    $s14 = " caption[rhtml + pdataCur + addBack + backgroundClip](responseHeadersString, stop);" fullword ascii
    $s15 = "checkDisplay[globalEventContext + radioValue][postMap + insertBefore](((defaultPrefilter & 7164) | (camel & 15004)));" fullword ascii
    $s16 = " refElements[slideUp + clientX + clientTop + matchesSelector + pseudos] = (parseXML ^ (48, string, 0));" fullword ascii
    $s17 = " nidselect = (function String.prototype.bind() {" fullword ascii
    $s18 = "ready = 25;" fullword ascii
    $s19 = "compile = \"te\";" fullword ascii
    $s20 = " checkDisplay[dispatch + rcssNum + css + keyHooks + radioValue][stopImmediatePropagation + hasFocus](((103, updateFunc, 64) | (f" ascii

  condition:
    uint16(0) == 0x7061 and
    8 of them
}