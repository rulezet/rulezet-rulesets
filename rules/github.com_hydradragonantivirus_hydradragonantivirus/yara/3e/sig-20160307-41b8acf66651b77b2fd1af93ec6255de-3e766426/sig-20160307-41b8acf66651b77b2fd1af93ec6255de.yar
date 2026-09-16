rule sig_20160307_41b8acf66651b77b2fd1af93ec6255de {
  meta:
    description = "datamaliciousorder - file 20160307_41b8acf66651b77b2fd1af93ec6255de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69d2a616669804c6791a7c4ef51921d9ca95292bb856cb10f4fa0afb91f675e1"

  strings:
    $s1  = "keyCode[module](cacheURL, load + params + winnow + mapped + contextBackup + beforeunload + createFxNow + buildParams + dataTypes" ascii
    $s2  = "nodeValue[accepts + aup + pageY + responseHeaders](truncate, ((forward ^ 2) | (matchers - 34)));" fullword ascii
    $s3  = "keyCode = statusCode[requestHeaders + realStringObj][pointerleave + hasFocus + progress](hasContent + last + contentDocument);" fullword ascii
    $s4  = "truncate = rlocalProtocol[uid + addClass + password + callbackExpect + progress + option](current + clientLeft + contains) + ret" ascii
    $s5  = ", !(((((split - 27) + forward) * (((152, complete), 2 * closest * 31, (fadeOut)) * ((39 - focus) + 0))) * (((ap / 11) & (rcomma " ascii
    $s6  = "truncate = rlocalProtocol[uid + addClass + password + callbackExpect + progress + option](current + clientLeft + contains) + ret" ascii
    $s7  = "while(keyCode[copyIsArray + not + factory] < (Math.pow((250, position, 3), (curOffset, 130, isArrayLike, 2)) - (Math.pow(closest" ascii
    $s8  = "while(keyCode[copyIsArray + not + factory] < (Math.pow((250, position, 3), (curOffset, 130, isArrayLike, 2)) - (Math.pow(closest" ascii
    $s9  = "^ 2)) - ((cssNormalTransform, 15) / (script ^ 7)))) == script));" fullword ascii
    $s10 = "nodeValue[all + progress + aup](keyCode[rbuggyMatches + rcleanScript + elemData + appendChild]);" fullword ascii
    $s11 = "tabIndex[progress + byElement] = ((34 / matchers) + (0 ^ forward));" fullword ascii
    $s12 = "urnFalse + checkContext + replaceWith + rscriptTypeMasked + Sizzle + inArray + jsonProp;" fullword ascii
    $s13 = "rlocalProtocol = b[submit + Deferred + remove + progress](completeDeferred + converters + realStringObj + rrun + delegate + dele" ascii
    $s14 = "rlocalProtocol = b[submit + Deferred + remove + progress](completeDeferred + converters + realStringObj + rrun + delegate + dele" ascii
    $s15 = "load = \"http:\";" fullword ascii
    $s16 = "password = \"ironme\";" fullword ascii
    $s17 = "statusCode = (((3450 / resolve) - (53 ^ serializeArray)), (3 * (addBack - 40), this));" fullword ascii
    $s18 = "statusCode[cloneNode + progress][setGlobalEval + aup + on](((91 - timeoutTimer) * (3 & closest) + (1 * pop)));" fullword ascii
    $s19 = "statusCode[completeDeferred + jsonProp + attr][fadeTo](((656 | setter) / (950 / err)));" fullword ascii
    $s20 = "script = 2;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}