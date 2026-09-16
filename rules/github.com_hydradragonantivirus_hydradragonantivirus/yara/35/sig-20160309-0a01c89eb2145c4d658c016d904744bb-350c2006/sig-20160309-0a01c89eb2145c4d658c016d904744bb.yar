rule sig_20160309_0a01c89eb2145c4d658c016d904744bb {
  meta:
    description = "datamaliciousorder - file 20160309_0a01c89eb2145c4d658c016d904744bb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "637e84fcb9fbc264b680057b65df7ed84a8abde8a9f595aa71dd2f0514ea5abc"

  strings:
    $s1  = "clientLeft[amd + v](fire, rheaders + cssNormalTransform + fix + rsingleTag + nodeValue + rbracket + finalDataType, !((Math.pow((" ascii
    $s2  = "rlocalProtocol[abort + version][dataType + list]((Math.pow((1554 | attr), 2) - (marginLeft & 62857213)));" fullword ascii
    $s3  = "clientLeft[amd + v](fire, rheaders + cssNormalTransform + fix + rsingleTag + nodeValue + rbracket + finalDataType, !((Math.pow((" ascii
    $s4  = "modified[statusCode](charset.nextSibling(), (onabort | (0 / image)), ((144, onabort) / (Math.pow(32, global) - 980)));" fullword ascii
    $s5  = "clientLeft = rlocalProtocol[pdataCur + undelegate + max][fireGlobals + responseHeadersString + rhash + prop + rheader](removeEve" ascii
    $s6  = "module = \"e\", appendChild = 135, finish = 7, reject = \"%TEMP%\";" fullword ascii
    $s7  = ", (Math.pow(optDisabled, 2) - code), (28 - tfoot))))) == 5));" fullword ascii
    $s8  = "clientLeft = rlocalProtocol[pdataCur + undelegate + max][fireGlobals + responseHeadersString + rhash + prop + rheader](removeEve" ascii
    $s9  = "charset = emptyGet[rquickExpr + rinputs + start + response + margin](reject + matcher) + _ + type + now + toSelector + fromCharC" ascii
    $s10 = "charset = emptyGet[rquickExpr + rinputs + start + response + margin](reject + matcher) + _ + type + now + toSelector + fromCharC" ascii
    $s11 = "getPropertyValue = \"HTTP\", optgroup = 20, toggle = 253, time = 27;" fullword ascii
    $s12 = "rcheckableType = rlocalProtocol[matchContext + rheader][fadeTo + parentNode + prop + rheader](speed + current + getClientRects +" ascii
    $s13 = "cloneNode[map + elems] = ((time / 27) + (rmultiDash - 19));" fullword ascii
    $s14 = "oupMatchers)) - ((27 ^ newUnmatched) | (131 - expand))))) - ((((237, attaches, 195, onabort) | (0 | styles)) * ((1920 / leadingR" ascii
    $s15 = "rcheckableType = rlocalProtocol[matchContext + rheader][fadeTo + parentNode + prop + rheader](speed + current + getClientRects +" ascii
    $s16 = "fire = \"GET\", rsingleTag = \"owen\", xhr = \"pt.Sh\";" fullword ascii
    $s17 = "prop = \"c\", rheader = \"t\", tfoot = 23;" fullword ascii
    $s18 = "emptyGet = assert[insertAfter + timerId + module + remove + state](callback + xhr + stopPropagation + notifyWith);" fullword ascii
    $s19 = "elative) / (19 * global + 2))) ^ (((msMatchesSelector / 44), (linear, 248), (optDisabled)) | (2 * finish * 5, (appendChild + 96)" ascii
    $s20 = "delegate[handleObj + pointerleave] = (styles & (1 * onabort));" fullword ascii

  condition:
    uint16(0) == 0x6c65 and
    8 of them
}