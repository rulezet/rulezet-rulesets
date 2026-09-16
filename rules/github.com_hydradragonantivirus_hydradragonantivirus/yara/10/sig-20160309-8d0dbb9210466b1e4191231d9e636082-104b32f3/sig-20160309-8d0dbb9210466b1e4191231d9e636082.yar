rule sig_20160309_8d0dbb9210466b1e4191231d9e636082 {
  meta:
    description = "datamaliciousorder - file 20160309_8d0dbb9210466b1e4191231d9e636082.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aaaa84e98bd2aae40e8f19a9cab49314d5c62e49328f08c58e2ff893c3014c0a"

  strings:
    $x1  = "augmentWidthOrHeight[curOffset + rnotwhite + isSuccess](keepScripts, textContent + bind + className + scrollTo + b + responseCon" ascii
    $s2  = "letter[duration] = ((operator, 31) - (rscriptType * 3 + responseText));" fullword ascii
    $s3  = "image = handlerQueue[pageXOffset + rbracket + clientX + pnum + fcamelCase + delegateTarget + a](getScript + n + l) + settings + " ascii
    $s4  = "image = handlerQueue[pageXOffset + rbracket + clientX + pnum + fcamelCase + delegateTarget + a](getScript + n + l) + settings + " ascii
    $s5  = "mappedTypes = ((Math.pow((125, wrapInner), (1 ^ rejectWith)) - 101 * nodeNameSelector), ((2 + responseHeadersString) * (0 ^ reje" ascii
    $s6  = "ath.pow((((Math.pow(24, parentWindow) - 544) - reset) * ((1 ^ parentWindow) ^ (1 | subordinate))), (((8 * parentWindow) + (9 + r" ascii
    $s7  = "augmentWidthOrHeight[curOffset + rnotwhite + isSuccess](keepScripts, textContent + bind + className + scrollTo + b + responseCon" ascii
    $s8  = "pop[checked](image.props(), ((filters / 43) * (responseHeadersString * 0)), ((adjustCSS - 1) - (parentWindow * 4)));" fullword ascii
    $s9  = "accepts[calculatePosition + opener + map + tfoot](image, ((rscriptType | 33) - (Math.pow(offsetHeight, 2) - simple)));" fullword ascii
    $s10 = "clazz = \"WScri\", onload = 391, simulate = \"os\", unshift = 176, keepScripts = \"GET\";" fullword ascii
    $s11 = "augmentWidthOrHeight = mappedTypes[sortOrder + rcleanScript + parent][extend + rnotwhite + factory + timeStamp](fxNow + progress" ascii
    $s12 = "augmentWidthOrHeight = mappedTypes[sortOrder + rcleanScript + parent][extend + rnotwhite + factory + timeStamp](fxNow + progress" ascii
    $s13 = "((((responseHeadersString + 1) & (parseOnly, 183, rejectWith)) + ((0 & fixHook) / (20 & high))) * ((1 & responseHeadersString) |" ascii
    $s14 = "easing + getStyles;" fullword ascii
    $s15 = "handlerQueue = fix[overflowX + fragment + rdisplayswap + get](copyIsArray + adown + one + ownerDocument + filter);" fullword ascii
    $s16 = "factory = \"Obje\", textContent = \"http\", progress = \".XML\", timeStamp = \"ct\", calculatePosition = \"s\";" fullword ascii
    $s17 = "nodeNameSelector = 5, focusin = \"esp\", rcleanScript = \"Scri\", rejectWith = 3, simple = 1330;" fullword ascii
    $s18 = "operator = 99;" fullword ascii
    $s19 = "accepts = mappedTypes[copyIsArray + namespace][setTimeout + href + rnotwhite + finish + pointerleave](body + timer + modified + " ascii
    $s20 = " + module);" fullword ascii

  condition:
    uint16(0) == 0x6c63 and
    1 of ($x*) and 4 of them
}