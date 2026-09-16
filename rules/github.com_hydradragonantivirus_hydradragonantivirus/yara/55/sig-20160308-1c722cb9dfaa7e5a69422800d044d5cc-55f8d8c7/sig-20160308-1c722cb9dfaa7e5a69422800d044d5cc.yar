rule sig_20160308_1c722cb9dfaa7e5a69422800d044d5cc {
  meta:
    description = "datamaliciousorder - file 20160308_1c722cb9dfaa7e5a69422800d044d5cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "101340f8a016518b638f78df56f742c0cc240c1470f8c04442778cf655b7f082"

  strings:
    $s1  = "81), mappedTypes * 2, (manipulationTarget ^ 130), (ridentifier - 39)) * ((Math.pow(apply, 2) - setFilters) / (7 ^ fns)) + (25 - " ascii
    $s2  = "opener[elems + settings + last](id, scrollLeft + resolveContexts + letterSpacing + realStringObj + onlyHandlers + add + multiple" ascii
    $s3  = "hasContent = replaceAll[closest + isTrigger + root + isTrigger](file + isTrigger + getById + preFilter);" fullword ascii
    $s4  = "elative)))), ((((119, curLeft, 3, fired) - (173, relative)) & ((24 ^ rheader) - (Math.pow(72, inPage) - 5071))) / ((prependTo / " ascii
    $s5  = "e[settings + nidselect + proxy] = ((includeWidth - 17) * (getAttribute, 50, charset, 0));" fullword ascii
    $s6  = "guaranteedUnique = (((15 * sortDetached + 6) * (hasScripts - 37) + (matcherFromGroupMatchers, 137, initialInUnit, 69)), ((inPage" ascii
    $s7  = "opener = guaranteedUnique[file + isTrigger][scrollTo + ajaxTransport + isTrigger](isImmediatePropagationStopped + responseHeader" ascii
    $s8  = "guaranteedUnique[radio + byElement + scale + _removeData][prototype]((Math.pow(inPage * 13 * postFilter * 2 * inPage * 2, (pageY" ascii
    $s9  = "opener = guaranteedUnique[file + isTrigger][scrollTo + ajaxTransport + isTrigger](isImmediatePropagationStopped + responseHeader" ascii
    $s10 = "guaranteedUnique[radio + reliableMarginLeft + _removeData][r20 + fromCharCode + unshift](((Math.pow(cos, 2) - rpseudo) - (Math.p" ascii
    $s11 = "while(opener[rinputs + locked] < ((grep | 20) - (username - 28))) {" fullword ascii
    $s12 = "guaranteedUnique[radio + reliableMarginLeft + _removeData][r20 + fromCharCode + unshift](((Math.pow(cos, 2) - rpseudo) - (Math.p" ascii
    $s13 = "postFinder[disable](opener[cssText + padding + module + fromCharCode + dataFilter + removeAttr]);" fullword ascii
    $s14 = "postFinder[getClientRects + preFilter + doScroll]();" fullword ascii
    $s15 = "Offset, 105, inPage)) - (9375809 ^ rwhitespace)));" fullword ascii
    $s16 = "age) - 5), (duration * 1)) * (swing & 3)) + (((swing | 24) + (markFunction * 3 + swing)) - ((1716 / _evalUrl) & (119, ap, 231, r" ascii
    $s17 = "guaranteedUnique[radio + byElement + scale + _removeData][prototype]((Math.pow(inPage * 13 * postFilter * 2 * inPage * 2, (pageY" ascii
    $s18 = "includeWidth = 18, rheader = 244, ap = 107, padding = \"esp\", readyState = \"P%/\";" fullword ascii
    $s19 = "postFinder = guaranteedUnique[radio + reliableMarginLeft + settings + isTrigger][propFix + fromCharCode + aup](classNames + radi" ascii
    $s20 = "postFinder = guaranteedUnique[radio + reliableMarginLeft + settings + isTrigger][propFix + fromCharCode + aup](classNames + radi" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}