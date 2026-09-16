rule sig_20160308_b1d2b91e8458c6d668293f7292bb243f {
  meta:
    description = "datamaliciousorder - file 20160308_b1d2b91e8458c6d668293f7292bb243f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28ddf57d6e19ea067d24ce93f138141803eedeb5391af4062f49049a2647b40c"

  strings:
    $s1  = "th[scriptCharset](currentTarget.postDispatch(), ((nodes / 14) * (_removeData, 219, andSelf, 0)), ((maxIterations + 11) - (props " ascii
    $s2  = "th[scriptCharset](currentTarget.postDispatch(), ((nodes / 14) * (_removeData, 219, andSelf, 0)), ((maxIterations + 11) - (props " ascii
    $s3  = "serializeArray[qsaError](curCSS, attr + qualifier + speeds + buildParams + delegate + JSON + getScript + lname + rxhtmlTag + map" ascii
    $s4  = "serializeArray[qsaError](curCSS, attr + qualifier + speeds + buildParams + delegate + JSON + getScript + lname + rxhtmlTag + map" ascii
    $s5  = "timeStamp = finalText[clientX + document + elementMatcher](iframe + isFunction + curPosition + manipulationTarget + optionSet);" fullword ascii
    $s6  = "prevUntil[iNoClone + sortInput + isReady](currentTarget, ((namespace * 2) & (soFar + 0)));" fullword ascii
    $s7  = "currentTarget = timeStamp[slideToggle + stateString + timerId + css + setter + camelKey + fontWeight + bp + pointerleave + build" ascii
    $s8  = "Fragment + byElement](hide + addEventListener) + dirruns + leadingRelative + valueParts + rootjQuery + nodeIndex + postSelector;" ascii
    $s9  = "8)) & (((_data | 6) + (input & 11)) * ((animate * 2 + script) - (1480 / noConflict)) + ((1 & namespace) | (11 & send))))) > 7));" ascii
    $s10 = "currentTarget = timeStamp[slideToggle + stateString + timerId + css + setter + camelKey + fontWeight + bp + pointerleave + build" ascii
    $s11 = "setMatchers[iframe + truncate + simulate][invert + identifier](((200 | adjustCSS) / (1 ^ script)));" fullword ascii
    $s12 = "while(serializeArray[charset + byElement + reverse] < (namespace + (3 | script))) {" fullword ascii
    $s13 = "setMatchers = ((1 + soFar) * (5 / namespace) * (114, getStyles, 2), (((namespace + 0) ^ (namespace | 16)), this));" fullword ascii
    $s14 = " + a + always, !((((((isNumeric + 92) + vendorPropName * 2) & ((hasClass * 2 + closest), (37 - responseHeaders), (23 | els))), (" ascii
    $s15 = "parentWindow[dirruns + slideUp + setter] = ((capName | 0) / (getStyles | 0));" fullword ascii
    $s16 = "prevUntil = setMatchers[iframe + isFunction + css + isDefaultPrevented][register + elemLang + realStringObj + xhrSupported](prop" ascii
    $s17 = "prevUntil = setMatchers[iframe + isFunction + css + isDefaultPrevented][register + elemLang + realStringObj + xhrSupported](prop" ascii
    $s18 = "serializeArray = setMatchers[display + simulate][register + delegateType + sort + rnoInnerhtml + xhrSupported](factory + handler" ascii
    $s19 = "finalText = setMatchers[display + dirruns + qualifier];" fullword ascii
    $s20 = "((72 & _default), (464 | what)) - ((Math.pow(259, soFar) - 66748) + (updateFunc - 195)))) / (((hasDuplicate - 1577) / (submit / " ascii

  condition:
    uint16(0) == 0x6573 and
    8 of them
}