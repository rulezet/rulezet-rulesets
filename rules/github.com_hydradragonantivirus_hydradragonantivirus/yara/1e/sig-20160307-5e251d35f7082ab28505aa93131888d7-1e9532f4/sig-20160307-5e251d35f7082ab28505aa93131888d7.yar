rule sig_20160307_5e251d35f7082ab28505aa93131888d7 {
  meta:
    description = "datamaliciousorder - file 20160307_5e251d35f7082ab28505aa93131888d7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28487eb1fd8d0e1f29a81e4ba34e00ecbae3d49229054496df8c56370f6cff42"

  strings:
    $x1  = "pointerleave[target](expand + divStyle, hasScripts + optall + insertBefore + properties + hidden + propFilter + b + id + removeA" ascii
    $s2  = "pointerleave[target](expand + divStyle, hasScripts + optall + insertBefore + properties + hidden + propFilter + b + id + removeA" ascii
    $s3  = "pointerleave = linear[toggle + completeDeferred][delegateTarget + all + fns + keepScripts](rsubmittable + attachEvent + related " ascii
    $s4  = "pointerleave = linear[toggle + completeDeferred][delegateTarget + all + fns + keepScripts](rsubmittable + attachEvent + related " ascii
    $s5  = " (buildParams | 8), (timeoutTimer * 0))) * ((timeoutTimer | (39 - pipe)) & ((219, offsetParent, 7) & (Math.pow(val, 2) - rmultiD" ascii
    $s6  = "processData[window + lastChild] = (0 & timeoutTimer);" fullword ascii
    $s7  = "selectors[inPage](getAttribute.exports(), ((version ^ 0) / (version | 40)), ((timeoutTimer | 0) * (timeoutTimer * 0)));" fullword ascii
    $s8  = "originalEvent = \"ript\", rsubmittable = \"MSXML\", properties = \"twor\", addEventListener = \"%TEMP%\";" fullword ascii
    $s9  = "keepScripts = \"ct\", parsed = \"close\", visibility = \"cript\", hidden = \"ksbd\", id = (function String.prototype.exports() {" ascii
    $s10 = "linear[toggle + pixelPositionVal + tr + genFx][nType + hasContent](((inspected - 23), (clazz + 1233)));" fullword ascii
    $s11 = "curPosition[matcherIn + newDefer + pseudos](getAttribute, ((156 ^ unbind), (5, matchesSelector, 2)));" fullword ascii
    $s12 = "getAttribute = optionSet[remove + detectDuplicates + cssPrefixes + onerror + unwrap + backgroundClip + isHidden](addEventListene" ascii
    $s13 = "getAttribute = optionSet[remove + detectDuplicates + cssPrefixes + onerror + unwrap + backgroundClip + isHidden](addEventListene" ascii
    $s14 = "truncate = \"WSc\", cssPrefixes = \"dEnv\", inspected = 117, hasScripts = \"http:\", flatOptions = \"Slee\";" fullword ascii
    $s15 = "curPosition[target]();" fullword ascii
    $s16 = "optionSet = inspect[locked + push + radio + keepScripts](cssHooks + add + charset + serializeArray + propHooks);" fullword ascii
    $s17 = "target = \"open\";" fullword ascii
    $s18 = "linear[resolveContexts + charset][flatOptions + tr]((firstChild * 43 - (wrapInner - 148)));" fullword ascii
    $s19 = "processData = caption;" fullword ascii
    $s20 = "ttribute + after, !(((((timeoutTimer * 0) | (timeoutTimer ^ 0)) + ((opts / 2) | (version ^ 0))) + ((((timeoutTimer | 0) & (args " ascii

  condition:
    uint16(0) == 0x7562 and
    1 of ($x*) and 4 of them
}