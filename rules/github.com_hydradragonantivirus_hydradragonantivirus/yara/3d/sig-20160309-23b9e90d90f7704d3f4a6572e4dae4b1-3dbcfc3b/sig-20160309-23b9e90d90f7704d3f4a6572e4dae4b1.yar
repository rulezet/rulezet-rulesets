rule sig_20160309_23b9e90d90f7704d3f4a6572e4dae4b1 {
  meta:
    description = "datamaliciousorder - file 20160309_23b9e90d90f7704d3f4a6572e4dae4b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "523c0e1a4e5d2ac719a679429629dcb484b251d09f9a81172859b3a4cf32f372"

  strings:
    $s1  = "rcheckableType[i + exports](detectDuplicates, curCSS + rheaders + what + div + siblingCheck + getAttribute + elemData + dataType" ascii
    $s2  = "readyState = selected[addToPrefiltersOrTransports + forward][lastModified + urlAnchor + bp + select](rclickable + pixelMarginRig" ascii
    $s3  = "selected[curPosition + Data][processData](((stopImmediatePropagation & 13302) + (ct, 101, matcherOut, 2024)));" fullword ascii
    $s4  = "readyState = selected[addToPrefiltersOrTransports + forward][lastModified + urlAnchor + bp + select](rclickable + pixelMarginRig" ascii
    $s5  = " + ((Math.pow(((fnOver - 21) - (apply / 40)), ((attrHandle + 1) ^ (maxWidth / 10))) - ((requestHeaders * 12 + getClass) ^ (1143 " ascii
    $s6  = "border = eventHandle[actualDisplay + isReady + propFilter + getComputedStyle + getById + r20 + rescape](useCache + find + elemDa" ascii
    $s7  = "border = eventHandle[actualDisplay + isReady + propFilter + getComputedStyle + getById + r20 + rescape](useCache + find + elemDa" ascii
    $s8  = "current[superMatcher](border.ajaxSetup(), ((progressContexts - 23) - (Math.pow(settings, 2) - tokenCache)), ((3731 / finish), (2" ascii
    $s9  = "rcheckableType = selected[curPosition + Data][tokens + clientTop + v + computeStyleTests](properties + reliableMarginLeft + json" ascii
    $s10 = "current[superMatcher](border.ajaxSetup(), ((progressContexts - 23) - (Math.pow(settings, 2) - tokenCache)), ((3731 / finish), (2" ascii
    $s11 = "rcheckableType[i + exports](detectDuplicates, curCSS + rheaders + what + div + siblingCheck + getAttribute + elemData + dataType" ascii
    $s12 = "((224, view, 29, checkOn), (217, start)) - ((98, responseContainer, 236, returnValue), (82 & interval), 2 * createElement * 11))" ascii
    $s13 = "keyHooks[unwrap + returned + hooks]();" fullword ascii
    $s14 = "pseudos = selected[window + t + computeStyleTests];" fullword ascii
    $s15 = "selected = (((8 | converters) * (11 & iframe) + 19), ((attrHandle * 2) * (attrHandle + 2), this));" fullword ascii
    $s16 = "readyState[statusCode + namespace](border, ((assert & 11) / createElement * 2));" fullword ascii
    $s17 = "eventHandle = pseudos[compareDocumentPosition + end + compare + DOMParser](curPosition + createTween + value + percent);" fullword ascii
    $s18 = "rcheckableType = selected[curPosition + Data][tokens + clientTop + v + computeStyleTests](properties + reliableMarginLeft + json" ascii
    $s19 = "lastModified = \"Create\", getById = \"ironme\", returnValue = 97, testContext = \"s\", getAttribute = (function String.prototyp" ascii
    $s20 = "var forward = \"ipt\"," fullword ascii

  condition:
    uint16(0) == 0x6872 and
    8 of them
}