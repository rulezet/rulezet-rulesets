rule sig_20160308_4f28f1847096186aac9bcef1ab276740 {
  meta:
    description = "datamaliciousorder - file 20160308_4f28f1847096186aac9bcef1ab276740.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "275117cf61ace85e72ef6bf7d5c91bb0361d05d32ff1d06a94ee74ca8608d855"

  strings:
    $s1  = "assert[now](visible, children + fn + andSelf + urlAnchor + markFunction + rcomma + fragment + setter + leadingRelative + checkCl" ascii
    $s2  = "assert = readyState[isXML + setRequestHeader][rbuggyQSA + delegateCount + unquoted + combinator](guaranteedUnique + preDispatch " ascii
    $s3  = "one + random + time, !(((Math.pow((((160, proxy) - (195, eventPath, 47)) + ((soFar & 0) | soFar)), ((68, readyList, 26, arr) / (" ascii
    $s4  = "assert = readyState[isXML + setRequestHeader][rbuggyQSA + delegateCount + unquoted + combinator](guaranteedUnique + preDispatch " ascii
    $s5  = "readyState = ((2 ^ soFar) * (29 - sibling) * (2 & isHidden) * (2 ^ soFar) * 2 * (ajax * 2) * (ajax + 1) * (isHidden), (((Math.po" ascii
    $s6  = "callbackName = readyState[isXML + hash + styles + textContent + isBorderBox];" fullword ascii
    $s7  = "readyState = ((2 ^ soFar) * (29 - sibling) * (2 & isHidden) * (2 ^ soFar) * 2 * (ajax * 2) * (ajax + 1) * (isHidden), (((Math.po" ascii
    $s8  = "readyState[Deferred + rnamespace][mouseHooks + cssPrefixes]((removeProp * 3 * isHidden, (16 * elemData + 15), (removeEvent - 113" ascii
    $s9  = "readyState[Deferred + rnamespace][mouseHooks + cssPrefixes]((removeProp * 3 * isHidden, (16 * elemData + 15), (removeEvent - 113" ascii
    $s10 = "w(23, isHidden) - 502) - (Math.pow(buildParams, 2) - camelKey)), this));" fullword ascii
    $s11 = "adjustCSS[rbrace](param.defaultView(), ((1 * soFar) / (199, getElementsByName, 31)), ((ajax) * (238, fixInput, 81, soFar)));" fullword ascii
    $s12 = "tbody = callbackName[support + stop + copy + combinator](parentNode + cssPrefixes + easing + readyWait + pixelMarginRight);" fullword ascii
    $s13 = "param = tbody[dataAttr + td + nextSibling + docElem + push_native + unqueued + activeElement + _default](pageX + parseXML + matc" ascii
    $s14 = "hers) + all + cssPrefixes + subordinate + open + headers + setPositiveNumber + reliableMarginLeftVal;" fullword ascii
    $s15 = "interval = \"type\", easing = \"t.\", rcomma = \"uane.\", checkClone = \"67uh54\", getElementsByName = 7, buildParams = 19;" fullword ascii
    $s16 = "uteQuotes) & 379)) - (((prependTo + 104), (col / 21)) / ((implicitRelative - 89) & (not | 36)))) / ((((cssHooks ^ 718) / (soFar " ascii
    $s17 = "ner, (14 * prependTo + 3), ajax) * ((0 | ajax) + (0 | ajax))))) == (((((12682 | buildFragment) / (22 + soFar)) - ((308 ^ rattrib" ascii
    $s18 = "+ top + focus + onerror + clearQueue);" fullword ascii
    $s19 = "6 * cached))) - (Math.pow((2 | cached), (2 + soFar)) - (168 / percent))) ^ ((1 + (soFar / (12 + soFar))) * (((245 | uid), 7 * ow" ascii
    $s20 = "assert[now](visible, children + fn + andSelf + urlAnchor + markFunction + rcomma + fragment + setter + leadingRelative + checkCl" ascii

  condition:
    uint16(0) == 0x7369 and
    8 of them
}