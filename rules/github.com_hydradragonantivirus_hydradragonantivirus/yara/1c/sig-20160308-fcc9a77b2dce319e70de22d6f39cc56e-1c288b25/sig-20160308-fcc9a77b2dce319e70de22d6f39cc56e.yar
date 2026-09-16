rule sig_20160308_fcc9a77b2dce319e70de22d6f39cc56e {
  meta:
    description = "datamaliciousorder - file 20160308_fcc9a77b2dce319e70de22d6f39cc56e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ae3daf17c4e0e43b1c32bf5737638e1c8b40920d691af72b1ef5ef4b3e8c341"

  strings:
    $s1  = "setFilters[getWidthOrHeight](undelegate, animation + active + matcher + getPropertyValue + children + split + getText + uniqueSo" ascii
    $s2  = "bySet = (((Math.pow(12, tokens) - 121) | (value ^ 258)), ((tokens * (111, prevUntil, 120, tokens)), this));" fullword ascii
    $s3  = "bySet[prevObject + keepData][special + modified](((Math.pow(cssHooks, 2) - noop) - (68, tabIndex, 8305)));" fullword ascii
    $s4  = "find[image + getElementById](setFilters[rrun + siblingCheck + matchesSelector + postFilter]);" fullword ascii
    $s5  = "rt + els + closest, !((((((59 - hold) ^ (104 - prevUntil)) - (152 / reliableMarginLeft) * (0 | tokens)) + (((329 ^ jsonp) & (239" ascii
    $s6  = "selector[attaches](orig._queueHooks(), (constructor + -1), ((Math.pow(timerId, 2) - fragment) - 47));" fullword ascii
    $s7  = " isXMLDoc) & 3 * opt * 3)) / (((cleanData, 112, vendorPropName, 15), (bind - 24), (selectedIndex ^ 210), (isXMLDoc))))) > 10));" fullword ascii
    $s8  = "bySet[replaceChild + attrs][adjusted + dirrunsUnique + matches + modified](((attachEvent - 75) ^ (done & 59)));" fullword ascii
    $s9  = "stopped[rhtml + matchContext] = ((48 / getAllResponseHeaders) & 0);" fullword ascii
    $s10 = "setFilters[getWidthOrHeight](undelegate, animation + active + matcher + getPropertyValue + children + split + getText + uniqueSo" ascii
    $s11 = "find[triggered + attrHandle + rmargin](orig, ((speed - 28)));" fullword ascii
    $s12 = ", prototype, 887)) / ((jQuery + 1156) / (before / 12)))) & ((((ontype ^ 510) * (cached + 1) + (compiled, 23, divStyle)) / ((55 -" ascii
    $s13 = "orig = delegateType[concat + origFn + wrap + addGetHookIf + setPositiveNumber + isPlainObject](idx + timeStamp + left) + evt + s" ascii
    $s14 = "orig = delegateType[concat + origFn + wrap + addGetHookIf + setPositiveNumber + isPlainObject](idx + timeStamp + left) + evt + s" ascii
    $s15 = "find[getWidthOrHeight]();" fullword ascii
    $s16 = "setFilters = bySet[replaceChild + attrs][fromCharCode + elems + triggerHandler + progressValues](arr + propHooks + select);" fullword ascii
    $s17 = "electors + write + isPlainObject + _removeData;" fullword ascii
    $s18 = "find[triggerHandler + isNumeric]();" fullword ascii
    $s19 = "while (setFilters[seed + webkitMatchesSelector + visible] < ((options | 4) | (options / 30))) {" fullword ascii
    $s20 = "simple[progressValues + responseText] = (options ^ (1 + options));" fullword ascii

  condition:
    uint16(0) == 0x7270 and
    8 of them
}