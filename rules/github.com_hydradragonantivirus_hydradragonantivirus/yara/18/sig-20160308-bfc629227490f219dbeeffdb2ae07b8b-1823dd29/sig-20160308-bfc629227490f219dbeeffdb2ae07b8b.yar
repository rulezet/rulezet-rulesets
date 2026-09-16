rule sig_20160308_bfc629227490f219dbeeffdb2ae07b8b {
  meta:
    description = "datamaliciousorder - file 20160308_bfc629227490f219dbeeffdb2ae07b8b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6bd0c9e27f12955c539aede72814f97f9b5e4efc61da073a797ef00db9c70a1f"

  strings:
    $s1  = "matcherFromGroupMatchers[compare + random + name][ajaxTransport]((Math.pow(matches * 509, (pattern)) - (3288932376 / overflowX))" ascii
    $s2  = "matcherFromGroupMatchers[compare + random + name][ajaxTransport]((Math.pow(matches * 509, (pattern)) - (3288932376 / overflowX))" ascii
    $s3  = "requestHeadersNames = sel[old + a + _$ + name](src + byElement + transport);" fullword ascii
    $s4  = "t) + -(1 ^ selectedIndex)) | ((Math.pow(18, pattern) - 301), (uid, 193, flatOptions, 173), (prevObject / 45), (timeout)))) ^ (((" ascii
    $s5  = "matcherFromGroupMatchers[swap + curPosition + rparentsprev][dataTypeExpression + conditionFn](((elementMatcher - 17) ^ (exports " ascii
    $s6  = "matcherFromGroupMatchers[swap + curPosition + rparentsprev][dataTypeExpression + conditionFn](((elementMatcher - 17) ^ (exports " ascii
    $s7  = "clone[addToPrefiltersOrTransports](t.memory(), ((1 + -timeout) & (12 / fn)), (0 | selectedIndex));" fullword ascii
    $s8  = "contains[conditionFn + qsa + scripts + finalDataType] = ((JSON | 153), (when & 63), (selectedIndex & 0));" fullword ascii
    $s9  = "fxNow = matcherFromGroupMatchers[src + pixelMarginRight + original][chainable + doScroll + start](getClientRects + ct + tuples);" ascii
    $s10 = "transport = \"Shell\";" fullword ascii
    $s11 = "swing[parseJSON](removeData, end + ajaxPrefilter + rbuggyQSA + offsetHeight + keepData + rnotwhite + camel + elems + setAttribut" ascii
    $s12 = "while(swing[isSimulated + classes + slideUp + display] < (Math.pow((pattern + 1), (to - 48)) - (timeout | 5))) {" fullword ascii
    $s13 = "setAttribute = \".f\", lastModified = \"xpa\", curPosition = \"cr\", current = \".scr\";" fullword ascii
    $s14 = "locked = \"TEMP%\";" fullword ascii
    $s15 = "clone = requestHeadersNames;" fullword ascii
    $s16 = "t = requestHeadersNames[newUnmatched + lastModified + responseHeaders + postSelector + responseType + callback + reverse + bubbl" ascii
    $s17 = "t = requestHeadersNames[newUnmatched + lastModified + responseHeaders + postSelector + responseType + callback + reverse + bubbl" ascii
    $s18 = "matcherFromGroupMatchers = (((88 & pop) | (138, rchecked, 118)), (((timeout ^ 2), (dataType + 6)), this));" fullword ascii
    $s19 = "reliableMarginRight[high] = (1 & (timeout * 1));" fullword ascii
    $s20 = "fxNow[opt + expanded]();" fullword ascii

  condition:
    uint16(0) == 0x7562 and
    8 of them
}