rule sig_20160309_4072fffe5598e414389252fe7014030f {
  meta:
    description = "datamaliciousorder - file 20160309_4072fffe5598e414389252fe7014030f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01daa99ccb7928323df3135e5ddd89614ef7977c0b79af84d3ed4bba3d638f5a"

  strings:
    $s1  = "cors[window + dataTypeExpression + rcssNum](margin, name + JSON + button + fx + constructor + callbackInverse + cssExpand + getA" ascii
    $s2  = "onverters) + ((2368 / winnow), 3 * animation * 3, (matcherOut & 2))) - (Math.pow(((_data - 31) + (unwrap - 47)), ((scriptCharset" ascii
    $s3  = " | 29) - (handlerQueue + 0))) - ((compiled & 507) / (charset - 40))))) == ((((Math.pow(padding, 2) - matcherIn) - ((128 ^ lastMo" ascii
    $s4  = " onreadystatechange) / (Math.pow(26, firing) - 645)) * ((converters | (1 * converters)) * ((8 / win) + (87, selectedIndex)))))))" ascii
    $s5  = "timerId[outermostContext + factory + num + ajaxTransport][scrollTo](((rscriptTypeMasked) ^ 281 * progressValues * 2));" fullword ascii
    $s6  = "idx = oldfire[v + setup + num + nodeNameSelector + defer + unbind + getBoundingClientRect + cssText](propName + filter) + reques" ascii
    $s7  = "height = timerId[password + pointerenter + factory + num + dataTypeExpression + isNumeric];" fullword ascii
    $s8  = "cors = timerId[classNames + isWindow][setRequestHeader + off](cur + conv2 + active + temp + parse);" fullword ascii
    $s9  = "propName = \"%TEMP%\";" fullword ascii
    $s10 = "dified) / (Math.pow(21, firing) - 415))) * ((converters & (9 / minWidth)) * ((1 * firing) | (3 & firing)))) + (((17, rquery, 83," ascii
    $s11 = "idx = oldfire[v + setup + num + nodeNameSelector + defer + unbind + getBoundingClientRect + cssText](propName + filter) + reques" ascii
    $s12 = "oldfire = height[setRequestHeader + isSimulated + rnotwhite + hidden](visible + rbracket + traditional);" fullword ascii
    $s13 = "margin = \"GET\", num = \"i\", resolve = 16, pointerenter = \"S\", combinator = \"ateO\";" fullword ascii
    $s14 = "tHeadersNames + jsonpCallback + seekingTransport + pixelMarginRightVal + factory;" fullword ascii
    $s15 = "var password = \"W\"," fullword ascii
    $s16 = "ll + cssText + preMap + opacity, !((((((checkbox & 63) & (progressValues ^ 44)) & ((acceptData / 5) - (converters | 6))) - (((se" ascii
    $s17 = "var temp = \"H\"," fullword ascii
    $s18 = "mimeType = \"send\", pageX = \"po\", hidden = \"ct\", setGlobalEval = \"Res\", XMLHttpRequest = \"type\";" fullword ascii
    $s19 = "timerId = (((12 / firing), (3 & matcherOut), (159 & disable)), (((50, progressValues, 115, classCache) & (Math.pow(10, firing) -" ascii
    $s20 = "name = \"h\", lastModified = 28, dataTypeExpression = \"p\", getAll = \"tem/lo\", getBoundingClientRect = \"trin\", isNumeric = " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}