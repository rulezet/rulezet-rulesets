rule sig_20160308_2bfb86928cce685c9f5bc2d1fb404ef5 {
  meta:
    description = "datamaliciousorder - file 20160308_2bfb86928cce685c9f5bc2d1fb404ef5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e18afe528afe9bbf8a9f122d8b5f6646b59e1ffe1de4ef2dfa65ba98dc8e18d"

  strings:
    $s1  = "readyState[host + rscriptTypeMasked + rcomma](xhrFields, pos + serializeArray + removeAttr + isBorderBox + onload + setter + rpa" ascii
    $s2  = "fadeOut[inspect + disableScript + nextSibling + rcomma] = ((easing | 0), (restoreScript ^ 9), (Math.pow(namespaces, 2) - url), (" ascii
    $s3  = "fadeOut[inspect + disableScript + nextSibling + rcomma] = ((easing | 0), (restoreScript ^ 9), (Math.pow(namespaces, 2) - url), (" ascii
    $s4  = "readyState = getResponseHeader[curElem + disableScript][dataPriv + getAll + conv](complete + checkContext + jsonProp);" fullword ascii
    $s5  = "readyState[host + rscriptTypeMasked + rcomma](xhrFields, pos + serializeArray + removeAttr + isBorderBox + onload + setter + rpa" ascii
    $s6  = "cssExpand = hide[getJSON + copyIsArray + pushStack + conv2 + getAttribute + matchedCount + disableScript + stopPropagation + hid" ascii
    $s7  = "propFilter = getResponseHeader[curElem + disableScript][dataPriv + disableScript + trim + disableScript](rtrim + once);" fullword ascii
    $s8  = "cssExpand = hide[getJSON + copyIsArray + pushStack + conv2 + getAttribute + matchedCount + disableScript + stopPropagation + hid" ascii
    $s9  = "aup[disableScript + nonce] = ((parseOnly * 0) | (insertAfter - 24));" fullword ascii
    $s10 = "while (readyState[animation + prefilterOrFactory + nodeNameSelector + rscriptTypeMasked] < ((9 - reverse) ^ (16 - gotoEnd))) {" fullword ascii
    $s11 = "getResponseHeader[modified + originalOptions + body][compile]((4 ^ parseOnly) * (60 / type) * (0 ^ diff) * (5 & ignored));" fullword ascii
    $s12 = "getResponseHeader = (((119, optSelected, 2310) / (specified & 23)), ((keyHooks * 2, (parseOnly + 2)), this));" fullword ascii
    $s13 = "getResponseHeader[modified + pnum + pseudo][compile]((3 * getAllResponseHeaders * 131 * iterator ^ (464 * propName + 241)));" fullword ascii
    $s14 = "^ ((100 + expando), (154 ^ prefix), (936 / defaultPrevented), (41 & lang))) + ((Math.pow((24 + lang), (1 * diff)) - (6417 | hold" ascii
    $s15 = "hide = structure[html + err + createHTMLDocument + load](acceptData + matcher + isArrayLike + getById);" fullword ascii
    $s16 = "((((244, seed, 1) * (parseOnly & 1)) * ((getElementById * 3) / (iNoClone - 5))) * (((getClass * 2 + indirect), (13 & fireWith)) " ascii
    $s17 = "structure = getResponseHeader[stateVal + matchers + m];" fullword ascii
    $s18 = "readyState[events + reject]();" fullword ascii
    $s19 = "Ready)) / ((31 & rejectWith)))), (((72 | gotoEnd) / (44 | propName)) & (1 + parseOnly)) * ((0 / diff) ^ 2)) == propName));" fullword ascii
    $s20 = "gotoEnd = 16, parentWindow = \"te\", disableScript = \"t\", matcher = \"pt.\", nodeNameSelector = \"ystat\";" fullword ascii

  condition:
    uint16(0) == 0x6567 and
    8 of them
}