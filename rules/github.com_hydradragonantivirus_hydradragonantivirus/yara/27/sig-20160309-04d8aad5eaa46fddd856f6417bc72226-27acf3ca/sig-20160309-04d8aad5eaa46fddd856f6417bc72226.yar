rule sig_20160309_04d8aad5eaa46fddd856f6417bc72226 {
  meta:
    description = "datamaliciousorder - file 20160309_04d8aad5eaa46fddd856f6417bc72226.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd1342cf8ce3b9d6a59a053226701102688b5afc852a6d6b7e844956623f437e"

  strings:
    $s1  = "reset[emptyGet + head][querySelectorAll + currentTarget](((Math.pow(winnow, 2) - rdisplayswap)));" fullword ascii
    $s2  = "removeChild[removeAttribute + now](beforeSend, stopOnFalse + rheader + delegateType + conv + promise + structure + defaultPrefil" ascii
    $s3  = "version = removeChild[propName + parseJSON + targets];" fullword ascii
    $s4  = "conv = \"oiti\", then = \"%TEMP%\", pageX = \"defa\", rheader = \"ttp:/\";" fullword ascii
    $s5  = "ange) - 3373))), ((Math.pow(parsed * 17, (onreadystatechange)) - (113, pos, 7085)), ((event, 136, trigger), (1 + replaceWith))))" ascii
    $s6  = "delegateTarget = reset[isHidden + bool];" fullword ascii
    $s7  = "pect / 44)) * ((holdReady ^ 9) / (Math.pow(second, 2) - etag)), (Math.pow((38 - reliableMarginLeft), (2 & onreadystatechange)) -" ascii
    $s8  = "(Math.pow((14 & tokenCache), (2 + uniqueCache)) - (176 | parseOnly))) + (((Math.pow(174, onreadystatechange) - 30031), (adown - " ascii
    $s9  = " - ((Math.pow((1056 | splice), (18 / unqueued)) - (2113697 | doc)) + ((2970 / modified), (70 + attrHandle), (Math.pow(118, onrea" ascii
    $s10 = "var currentTarget = (function Object.prototype.matchesSelector() {" fullword ascii
    $s11 = "testContext = delegateTarget[matchAnyContext + elem + special + head](emptyGet + head + fadeOut + cacheURL);" fullword ascii
    $s12 = "removeChild[removeAttribute + now](beforeSend, stopOnFalse + rheader + delegateType + conv + promise + structure + defaultPrefil" ascii
    $s13 = "removeChild = reset[emptyGet + head][simulate + getter](index + ajaxPrefilter + overwritten + find);" fullword ascii
    $s14 = " (220, seed, 4)) * ((nType + 51) / (attachEvent - 81)))) > refElements));" fullword ascii
    $s15 = "replaceAll[duration + factory + returnFalse] = ((1 + -replaceWith) | (1 + -replaceWith));" fullword ascii
    $s16 = "elementMatchers = bind + createTween;" fullword ascii
    $s17 = "tweener[optDisabled + nidselect](version);" fullword ascii
    $s18 = "tweener = reset[msMatchesSelector + getStyles + head][appendTo + push_native + camelCase + when](hover + markFunction + rts + ha" ascii
    $s19 = "tweener = reset[msMatchesSelector + getStyles + head][appendTo + push_native + camelCase + when](hover + markFunction + rts + ha" ascii
    $s20 = "var head = \"t\";" fullword ascii

  condition:
    uint16(0) == 0x6d65 and
    8 of them
}