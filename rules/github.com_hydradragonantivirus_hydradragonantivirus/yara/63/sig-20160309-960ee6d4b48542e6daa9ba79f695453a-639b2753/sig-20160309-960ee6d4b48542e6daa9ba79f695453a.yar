rule sig_20160309_960ee6d4b48542e6daa9ba79f695453a {
  meta:
    description = "datamaliciousorder - file 20160309_960ee6d4b48542e6daa9ba79f695453a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef6fb677d2b2f8046e2e5e716ba0166fc2171206f3e4795d23a9b89249a7f067"

  strings:
    $s1  = "ridentifier[th](style, reliableMarginLeftVal + createComment + slideUp + allTypes + attrs + random + ignored + getStyles + match" ascii
    $s2  = "ridentifier[th](style, reliableMarginLeftVal + createComment + slideUp + allTypes + attrs + random + ignored + getStyles + match" ascii
    $s3  = "pagationStopped)), ((Math.pow(1324, insertBefore) - 1750961) / (transport | 9)), ((defaultPrefilter + 23) ^ (insertAfter))), (((" ascii
    $s4  = "rmsPrefix[ignored + left + disabled + dataTypeOrTransport + pixelMarginRightVal](fromCharCode, ((rchecked * 2) - (Math.pow(cssPr" ascii
    $s5  = "ridentifier = noCloneChecked[jsonp + parentNode + current][rnoContent + attachEvent + firstDataType + current](checkContext + su" ascii
    $s6  = "ridentifier = noCloneChecked[jsonp + parentNode + current][rnoContent + attachEvent + firstDataType + current](checkContext + su" ascii
    $s7  = "xhr = \"%TEMP%\"," fullword ascii
    $s8  = "rmsPrefix[ignored + left + disabled + dataTypeOrTransport + pixelMarginRightVal](fromCharCode, ((rchecked * 2) - (Math.pow(cssPr" ascii
    $s9  = "noCloneChecked[merge + cos + parseHTML][contexts + getClientRects](((1028 | classNames) ^ (11010 - MAX_NEGATIVE)));" fullword ascii
    $s10 = "startTime = 1, ajax = 21, checked = \"sen\", mouseHooks = 233, reliableMarginLeftVal = \"http:\";" fullword ascii
    $s11 = "rmsPrefix = noCloneChecked[globalEval + parseHTML][postDispatch + checkOn + current](rnumnonpx + split + rbuggyQSA);" fullword ascii
    $s12 = "ridentifier[checked + attrNames]();" fullword ascii
    $s13 = "rcssNum = ridentifier[define + constructor + anim];" fullword ascii
    $s14 = "nsertBefore * 2 * DOMParser * 2 * insertBefore * 2 + (setup + 13))), (((reliableMarginRight + 27) * (origFn / 3) + (Math.pow(unb" ascii
    $s15 = "noCloneChecked = (((51 + tr), (75 ^ preFilter), (4440 / sourceIndex)), (((315 / ofType) + (22 / binary)), this));" fullword ascii
    $s16 = "fromCharCode = location[chainable + key + high + configurable + handlerQueue + combinator + vendorPropName + n + teardown + comp" ascii
    $s17 = "fromCharCode = location[chainable + key + high + configurable + handlerQueue + combinator + vendorPropName + n + teardown + comp" ascii
    $s18 = "style = \"GET\"," fullword ascii
    $s19 = "location = markFunction[postDispatch + setTimeout + jQuery](unique + current + i);" fullword ascii
    $s20 = "}, \".Shell\"), disabled = \"eT\", orig = \"ogs/8\";" fullword ascii

  condition:
    uint16(0) == 0x656d and
    8 of them
}