rule sig_20160309_2179901b7a52b6fd54866f4b8ef052f2 {
  meta:
    description = "datamaliciousorder - file 20160309_2179901b7a52b6fd54866f4b8ef052f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b92c4896525171d6f847d4d4fffd6702a99ff41b535d67da2458a64b3217de59"

  strings:
    $s1  = "username = val[activeElement + rnoContent][soFar + rheaders + getJSON + createPositionalPseudo + arr](holdReady + Symbol + conte" ascii
    $s2  = "username = val[activeElement + rnoContent][soFar + rheaders + getJSON + createPositionalPseudo + arr](holdReady + Symbol + conte" ascii
    $s3  = "queue[parseXML + boolHook](buildParams, finalValue + valHooks + filter + done + register + dataTypeOrTransport + statusCode + se" ascii
    $s4  = "51)) - (Math.pow((getWidthOrHeight), (123, active, 90, teardown)) - (41352 + newUnmatched)))))));" fullword ascii
    $s5  = "username[els + rcleanScript + using](count, ((visible / 45) ^ (fireGlobals / 19)));" fullword ascii
    $s6  = "rquery[inspectPrefiltersOrTransports + using] = ((177, keepScripts, 2) / (teardown + 0));" fullword ascii
    $s7  = "val = (((660 + nativeStatusText) / (Math.pow(5, teardown) - 18)), ((Math.pow((input, 10), (teardown + 0)) - (originAnchor, 230, " ascii
    $s8  = "val = (((660 + nativeStatusText) / (Math.pow(5, teardown) - 18)), ((Math.pow((input, 10), (teardown + 0)) - (originAnchor, 230, " ascii
    $s9  = "ed + parseHTML, !(((Math.pow(((node / 44), (width - 63), (cssNumber ^ 0)), ((fireGlobals, 233), (isBorderBox * 4 + xhrSuccessSta" ascii
    $s10 = "queue = val[guid + doScroll + arr][to + image + arr + using + script + matchedCount](wrapAll + rjsonp + merge + outermost + reje" ascii
    $s11 = "val[mouseleave + eventPath][dirruns](((Math.pow(wrap, 2) - rtagName) * (39, prop) + (485 & runescape)));" fullword ascii
    $s12 = "queue = val[guid + doScroll + arr][to + image + arr + using + script + matchedCount](wrapAll + rjsonp + merge + outermost + reje" ascii
    $s13 = "wn) & ((16 ^ prop) / (200 / unwrap))))) == (((((6 ^ access) - (0 | selector)) + ((1 ^ attrHandle) ^ (3 & cssNumber)))) & (Math.p" ascii
    $s14 = "count = rinputs[errorCallback + includeWidth + getElementById + fcamelCase + clientLeft + using + eventDoc + bool + stopOnFalse]" ascii
    $s15 = "count = rinputs[errorCallback + includeWidth + getElementById + fcamelCase + clientLeft + using + eventDoc + bool + stopOnFalse]" ascii
    $s16 = " ((splice, 161, xhrSuccessStatus) * (131, outerCache, 0)))) - (Math.pow((Math.pow((cssNumber + 14), (teardown)) - 266), (flag - " ascii
    $s17 = "queue[parseXML + boolHook](buildParams, finalValue + valHooks + filter + done + register + dataTypeOrTransport + statusCode + se" ascii
    $s18 = "tus), 122, (onreadystatechange, 2))) - ((cssNumber & 2) * (elems, 76, teardown))) * (((3 * isBorderBox + 1) - (jsonpCallback & 2" ascii
    $s19 = "username[expanded + conv]();" fullword ascii
    $s20 = "errorCallback = \"Ex\", pixelMarginRight = 37, rfocusMorph = 193, script = \"Obje\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}