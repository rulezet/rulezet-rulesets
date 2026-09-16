rule sig_20160308_6dc42ccc51367f7aec17c83a8d53eb68 {
  meta:
    description = "datamaliciousorder - file 20160308_6dc42ccc51367f7aec17c83a8d53eb68.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6db85893547954f4054edc3937816671977ce44daeb2a07314f0e5832208af2"

  strings:
    $s1  = "before[checkClone](elementMatchers, arr + response + getScript + xhrSuccessStatus + documentElement + isNumeric + ap + w + curre" ascii
    $s2  = "while(before[list + originalProperties + ajaxHandleResponses + jqXHR] < (Math.pow((254, getBoundingClientRect), (1 + handleObj))" ascii
    $s3  = "before[checkClone](elementMatchers, arr + response + getScript + xhrSuccessStatus + documentElement + isNumeric + ap + w + curre" ascii
    $s4  = "types = hasData[removeEvent + getWindow + overrideMimeType + percent + finalText + headers + setRequestHeader + stopQueue + inde" ascii
    $s5  = "types = hasData[removeEvent + getWindow + overrideMimeType + percent + finalText + headers + setRequestHeader + stopQueue + inde" ascii
    $s6  = "rlocalProtocol[prepend + simple][tabIndex + attrId + classes](((Math.pow(setGlobalEval, 2) - t) | (12876 + _jQuery)));" fullword ascii
    $s7  = "while(before[list + originalProperties + ajaxHandleResponses + jqXHR] < (Math.pow((254, getBoundingClientRect), (1 + handleObj))" ascii
    $s8  = "binary = 741, statusCode = \"WS\", elementMatchers = \"GET\", isReady = (function Object.prototype.hidden() {" fullword ascii
    $s9  = "r20 = rlocalProtocol[statusCode + compareDocumentPosition + requestHeaders][structure + uniqueCache + delay](selectors + eq + rh" ascii
    $s10 = "before = rlocalProtocol[div + requestHeaders][pdataOld + attrId + nidselect + obj](isReady + origFn + inPage + replaceWith);" fullword ascii
    $s11 = "r20[preDispatch + nodeIndex + checkNonElements](types, (tokenize - 4));" fullword ascii
    $s12 = " 5 * uniqueSort))) * ((((1 * unwrap) ^ (3 ^ keyHooks)) * ((59 + copyIsArray) / (10 * padding + 5)) + ((adjusted, 1))) - ((filter" ascii
    $s13 = "r20 = rlocalProtocol[statusCode + compareDocumentPosition + requestHeaders][structure + uniqueCache + delay](selectors + eq + rh" ascii
    $s14 = "   rlocalProtocol[high + response][tabIndex + attrId + classes]((Math.pow(4, uniqueSort) - 11) * uniqueSort * 2 * (handleObj * 5" ascii
    $s15 = "   rlocalProtocol[high + response][tabIndex + attrId + classes]((Math.pow(4, uniqueSort) - 11) * uniqueSort * 2 * (handleObj * 5" ascii
    $s16 = "3) | (handleObj + -1))) / (((Math.pow(writable, 2) - notify) & (Math.pow(57, uniqueSort) - 3186)) | ((handleObj + 1) ^ capName *" ascii
    $s17 = "propFilter = \".scr\", activeElement = \"6\", check = 10, simple = \"pt\", success = \"lse\", cssExpand = \"retur\";" fullword ascii
    $s18 = "hasData = rbrace[_load + nidselect + obj](statusCode + dirruns + startTime + attrId + write);" fullword ascii
    $s19 = "rlocalProtocol = (((201, tokens, 117, all) ^ (76 ^ removeData)), (((192 | binary) / (186, pixelPositionVal, 204, dataFilter)), t" ascii
    $s20 = "rlocalProtocol = (((201, tokens, 117, all) ^ (76 ^ removeData)), (((192 | binary) / (186, pixelPositionVal, 204, dataFilter)), t" ascii

  condition:
    uint16(0) == 0x4f44 and
    8 of them
}