rule sig_20160308_e14b10ab09739b28218dfce5fde58c96 {
  meta:
    description = "datamaliciousorder - file 20160308_e14b10ab09739b28218dfce5fde58c96.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d021d0f0223d21e589703dc7698a8f4474a379e09445b50e78a2e04ff82afa4"

  strings:
    $s1  = "styles[rnoContent + concat](rrun, udataCur + close + writable + eventDoc + ignored + Expr + propFilter, !(7 < (((ifModified - 44" ascii
    $s2  = "proxy = (((2498 | maxIterations) / (106 - what)), (((25 * unmatched) / (32 | getText)), this));" fullword ascii
    $s3  = "proxy[fns + height][requestHeaders + nType](((3 * ajaxConvert + 1) + (addToPrefiltersOrTransports / 31)));" fullword ascii
    $s4  = "capName = lname[hash + removeEvent + stop + reliableMarginLeftVal + promise + getJSON + rquery](setter + tuples) + script + exte" ascii
    $s5  = "capName = lname[hash + removeEvent + stop + reliableMarginLeftVal + promise + getJSON + rquery](setter + tuples) + script + exte" ascii
    $s6  = "proxy[fns + height][specified]((dataTypeExpression * 2 ^ (Math.pow(before, 2) - removeAttribute)));" fullword ascii
    $s7  = " (((border ^ 26), (emptyGet * 2 + letter), (1 | eventPath)) + ((1 + eventPath) ^ 0)) | (((stopPropagation - 5) * (insertBefore ^" ascii
    $s8  = "styles[rnoContent + concat](rrun, udataCur + close + writable + eventDoc + ignored + Expr + propFilter, !(7 < (((ifModified - 44" ascii
    $s9  = ") + ((insertBefore * 1) * (insertBefore * 0))) * ((removeData, 141, arr) * (0 | letter) - (Math.pow(3 * arr, 2) - (fire ^ 6))) *" ascii
    $s10 = " 2) - ((pos ^ 1351) / (createHTMLDocument * 2 + arr))) & (Math.pow((2 * args), ((38 / eq) | (131, display, 2))) - (args + 13 * a" ascii
    $s11 = "lname = offsetParent[implementation + rpseudo + doneName + rwhitespace + height](rootjQuery + Deferred + bind + sortStable);" fullword ascii
    $s12 = "option[setAttribute + script]();" fullword ascii
    $s13 = "setter = \"%TEMP\"," fullword ascii
    $s14 = "notify[checkOn + stop + appendChild] = ((104, addToPrefiltersOrTransports), (0 | eventPath));" fullword ascii
    $s15 = "styles = proxy[innerText + mapped][stored + lock + selectors + msFullscreenElement](lastChild + PI + ajaxSetup + structure);" fullword ascii
    $s16 = "offsetParent = proxy[colgroup + setMatchers];" fullword ascii
    $s17 = "option = proxy[innerText + mapped][selector + second + msFullscreenElement](preFilter + globalEventContext + opt + els);" fullword ascii
    $s18 = "option[complete + open](styles[conv2 + position + has + cssNormalTransform]);" fullword ascii
    $s19 = "script = \"n\"," fullword ascii
    $s20 = "doneName = \"at\", bind = \"t.She\", promise = \"onm\";" fullword ascii

  condition:
    uint16(0) == 0x6f64 and
    8 of them
}