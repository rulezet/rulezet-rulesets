rule sig_20160308_d426e58a7c47eb8f3b75ef912dcc6a6a {
  meta:
    description = "datamaliciousorder - file 20160308_d426e58a7c47eb8f3b75ef912dcc6a6a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c401154d0f6414a421a3118623ee5d8902aa0406056777fdd89101cb181a11b"

  strings:
    $x1  = "disableScript[createHTMLDocument + processData + valHooks](toArray, bool + isXMLDoc + createHTMLDocument + newUnmatched + getEle" ascii
    $s2  = "disableScript = swing[superMatcher + processData + m][computeStyleTests + image + postDispatch](createPseudo + isArrayLike + aup" ascii
    $s3  = "disableScript = swing[superMatcher + processData + m][computeStyleTests + image + postDispatch](createPseudo + isArrayLike + aup" ascii
    $s4  = "disableScript[createHTMLDocument + processData + valHooks](toArray, bool + isXMLDoc + createHTMLDocument + newUnmatched + getEle" ascii
    $s5  = "matched = swing[merge + transports][computeStyleTests + currentTime + getPropertyValue + m](rquery + boxSizingReliableVal + hasC" ascii
    $s6  = "nType[processData + createHTMLDocument + contexts + leadingRelative] = ((Math.pow(6, selected) - 25) - (uniqueID | 11));" fullword ascii
    $s7  = "swing[merge + transports][dispatch + nodeIndex + processData](((queue ^ 3316) ^ (Math.pow(tuple, 2) - doAnimation)));" fullword ascii
    $s8  = "offsetParent[overflow](blur.manipulationTarget(), ((children ^ 24) - key), ((0 & fixHook)));" fullword ascii
    $s9  = "swing[merge + transports][td + processData](((implicitRelative & 2808) / (fadeOut - 21)));" fullword ascii
    $s10 = "matched = swing[merge + transports][computeStyleTests + currentTime + getPropertyValue + m](rquery + boxSizingReliableVal + hasC" ascii
    $s11 = "while(disableScript[vendorPropName + initialInUnit + results + round] < ((uniqueID & 0) ^ (fireWith - 28))) {" fullword ascii
    $s12 = "^ (Math.pow(655, selected) - 428072)) / (((adjustCSS | 4490) / (rcomma + 15)), ((optDisabled + 39) | (charCode - 7)), ((self + 0" ascii
    $s13 = "(((fixHook * 8) * selected + (1 * selected)) & ((25 + each))) | (((42 & addGetHookIf) - (35 - id)) & ((33 | stateString), (37 + " ascii
    $s14 = "xHook) & (((Math.pow(3 * stateString * 2 * selected * 2 * selected * 2, (selected & 3)) - (Math.pow(pdataCur, 2) - statusCode)) " ascii
    $s15 = "disableScript[initialInUnit + window]();" fullword ascii
    $s16 = "pdataCur = 48923, charCode = 39, toArray = \"GET\", getPropertyValue = (function Object.prototype.manipulationTarget() {" fullword ascii
    $s17 = "matched[top + round](disableScript[checkContext + num + namespace + push + noGlobal]);" fullword ascii
    $s18 = "ow)) / (0 | (container | 1))), ((uniqueID ^ 3) ^ selected * (0 | stateString))), ((1 * selected) & ((1 ^ stateString) ^ 0))) - (" ascii
    $s19 = "swing = ((13 | (cssHooks - 23)), (((markFunction * 5 + each), (16 | parseJSON)), this));" fullword ascii
    $s20 = ") * (rtypenamespace - 31) + (container, 4)))))));" fullword ascii

  condition:
    uint16(0) == 0x6f62 and
    1 of ($x*) and 4 of them
}