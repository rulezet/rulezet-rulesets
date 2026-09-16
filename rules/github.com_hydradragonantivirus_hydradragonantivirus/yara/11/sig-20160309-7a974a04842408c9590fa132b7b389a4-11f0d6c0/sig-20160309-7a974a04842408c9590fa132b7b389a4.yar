rule sig_20160309_7a974a04842408c9590fa132b7b389a4 {
  meta:
    description = "datamaliciousorder - file 20160309_7a974a04842408c9590fa132b7b389a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7d08224f39a1868e44b1537169b16ce8c81753151a21a94c6fdec3237fda7c2"

  strings:
    $x1  = "overwritten[overrideMimeType + matcherIn](always, curCSS + prependTo + cos + elemData + notifyWith + base + pageXOffset + rcombi" ascii
    $s2  = "file = \"ject\", overrideMimeType = \"o\", head = 139, param = \"pt\", forward = \"Ex\", rnative = \"cri\";" fullword ascii
    $s3  = "fromCharCode[get + rinputs + version + module](hookFn, ((elemLang | 28) - (Math.pow(calculatePosition, 2) - excess)));" fullword ascii
    $s4  = "(Math.pow((fail / 18), (unloadHandler | 2)) - (returnTrue ^ 16)) | ((timer ^ 46), (rnumnonpx + 5))) + ((unloadHandler * 83 - (ou" ascii
    $s5  = "fromCharCode = count[addCombinator + removeAttribute][len + rneedsContext + file](returnFalse + restoreScript + querySelectorAll" ascii
    $s6  = "fromCharCode = count[addCombinator + removeAttribute][len + rneedsContext + file](returnFalse + restoreScript + querySelectorAll" ascii
    $s7  = "termostContext, 116, head, 101)), (constructor | 15) * (fire - 23), (rquery / 13) * (rnumnonpx ^ 4) * (getWindow - 31) * (rnumno" ascii
    $s8  = "count = (((77 ^ rmsPrefix) & (90 + getWindow)), ((5 * onabort, (35 + offsetParent), (68 & token), 2), this));" fullword ascii
    $s9  = "overwritten = count[fireGlobals + input + param][postSelector + rinputs + removeAttribute + handlers + bool](conditionFn + bindT" ascii
    $s10 = "overwritten[overrideMimeType + matcherIn](always, curCSS + prependTo + cos + elemData + notifyWith + base + pageXOffset + rcombi" ascii
    $s11 = "overwritten = count[fireGlobals + input + param][postSelector + rinputs + removeAttribute + handlers + bool](conditionFn + bindT" ascii
    $s12 = "& 3) - (rnumnonpx)) | (0 ^ timer)) * ((3 & returnTrue) & (10 / args)) * ((Math.pow(8, unloadHandler) - 55) | (opacity - 76)), ((" ascii
    $s13 = "count[boolHook + rnative + param][adjustCSS](((16727 - rnamespace) ^ (Math.pow(6125, unloadHandler) - 37509005)));" fullword ascii
    $s14 = "currentTarget = queue;" fullword ascii
    $s15 = "fromCharCode[getResponseHeader + last](chainable);" fullword ascii
    $s16 = "hookFn = appendChild[forward + newDefer + sibling + iterator + rclass + matches + relative](tokens + preexisting + tweener + l +" ascii
    $s17 = "hookFn = appendChild[forward + newDefer + sibling + iterator + rclass + matches + relative](tokens + preexisting + tweener + l +" ascii
    $s18 = "nators + suffix + documentIsHTML + computed + realStringObj + mappedTypes + relative + uid + attrs + optgroup, !(((((returnTrue " ascii
    $s19 = "r20 = count[rootjQuery + createOptions];" fullword ascii
    $s20 = "tr = \"posit\", restoreScript = \".St\", send = \"dy\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}