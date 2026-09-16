rule sig_20160308_b81cc5d8075b3307c55002e4a987c905 {
  meta:
    description = "datamaliciousorder - file 20160308_b81cc5d8075b3307c55002e4a987c905.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1b338bc6ea1b419ef23463b2e853802f72320cc456078a90f2fcac023cb0f75"

  strings:
    $x1  = "hide[events](opts + box, _removeData + cloneNode + outermostContext + dataTypeOrTransport + contentType + matchesSelector + cont" ascii
    $s2  = ", (urlAnchor ^ 2)) - rootjQuery * 3)), (Math.pow(((content - 90) / rmultiDash * 3), ((replaceAll + 1) | (urlAnchor ^ 0))) - ((se" ascii
    $s3  = "ow(16, clone) - 227), (currentTarget & 255), (clone | 24)) - ((sortOrder, 165, clone) ^ (2 * pos)))))));" fullword ascii
    $s4  = "valueParts = clientLeft[attaches + inArray + nodeType + offsetParent + disableScript + count](nodeValue + onerror) + constructor" ascii
    $s5  = "markFunction = (((95 / replaceAll), (70 - completed)), ((2 ^ (Math.pow(isSuccess, 2) - ret)), this));" fullword ascii
    $s6  = "markFunction[tokenize + rlocalProtocol + sortStable][originalProperties + resolveContexts + selector]((26202 - (Math.pow(isFunct" ascii
    $s7  = "valueParts = clientLeft[attaches + inArray + nodeType + offsetParent + disableScript + count](nodeValue + onerror) + constructor" ascii
    $s8  = "markFunction[tokenize + rlocalProtocol + sortStable][originalProperties + resolveContexts + selector]((26202 - (Math.pow(isFunct" ascii
    $s9  = "hide[events](opts + box, _removeData + cloneNode + outermostContext + dataTypeOrTransport + contentType + matchesSelector + cont" ascii
    $s10 = "nodeValue = \"%TEMP%\";" fullword ascii
    $s11 = "ains + username + realStringObj + special + delegate + name, !(4 < (((((rmultiDash & 3) ^ rmultiDash * 3) | (Math.pow((obj / 41)" ascii
    $s12 = "clientLeft = parts[div1 + pointerenter + sortStable](adown + getAttributeNode + reset + handlers + win);" fullword ascii
    $s13 = "while (hide[refElements + dataAttr + postSelector + clearCloneStyle] < ((3 + clone) & (1 * letter))) {" fullword ascii
    $s14 = "boxSizingReliable[wrapAll](valueParts.lock(), ((createInputPseudo ^ 1) - (high)), ((0 ^ urlAnchor) & (22, urlAnchor)));" fullword ascii
    $s15 = "doneName[selector + ajaxSettings + preFilter] = ((replaceAll + -1) | (urlAnchor / 12));" fullword ascii
    $s16 = "ion, 2) - indirect)));" fullword ascii
    $s17 = "lected & 368502) / (completed))), (((20 & result) ^ 15) * ((urlAnchor | 0) | clone) + ((72 ^ shift) / (10 ^ letter))), (((Math.p" ascii
    $s18 = "charset = markFunction[adown + rrun + selector + sortStable][rtrim + curTop + add](dir + then + eventHandle);" fullword ascii
    $s19 = "markFunction[radioValue + unquoted + rlocalProtocol + sortStable][pixelMarginRight](((37, key) - (199 & isPropagationStopped)));" ascii
    $s20 = "clone = 2, getWindow = \"Han\", position = \"close\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}