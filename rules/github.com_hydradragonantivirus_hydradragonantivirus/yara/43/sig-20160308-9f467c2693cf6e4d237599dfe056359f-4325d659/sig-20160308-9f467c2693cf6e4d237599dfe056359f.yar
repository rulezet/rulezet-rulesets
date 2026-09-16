rule sig_20160308_9f467c2693cf6e4d237599dfe056359f {
  meta:
    description = "datamaliciousorder - file 20160308_9f467c2693cf6e4d237599dfe056359f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5aa670645b00fcbbe680333173e3381ef5fe0ef6a19cac9647a1d55873213d6f"

  strings:
    $s1  = "manipulationTarget[p](prevUntil.shift(), (pointerenter / (108 - collection)), ((16 - stopImmediatePropagation) / (33 / onabort))" ascii
    $s2  = "manipulationTarget[p](prevUntil.shift(), (pointerenter / (108 - collection)), ((16 - stopImmediatePropagation) / (33 / onabort))" ascii
    $s3  = "script[opt + postFilter](prevUntil, ((ajaxExtend, 2) + (pointerenter / 41)));" fullword ascii
    $s4  = "pixelMarginRight[preventDefault + hasCompare](createFxNow, ajaxConvert + tweens + currentValue + isWindow + scrollLeft + ontype " ascii
    $s5  = "script[matcherOut](pixelMarginRight[pdataCur + name + wrapAll + createComment]);" fullword ascii
    $s6  = "mediatePropagation)) / (((17 | msFullscreenElement) ^ (102 - values)) & ((552 - height) / (49, setMatched)))) | ((Math.pow(((59 " ascii
    $s7  = "while (pixelMarginRight[removeAttribute + wrap + cssText + onreadystatechange] < ((doneName / 7), (implementation + 15), (versio" ascii
    $s8  = "manipulationTarget = defer;" fullword ascii
    $s9  = "prevUntil = defer[target + timeout + msMatchesSelector + className + id + class2type](jsonProp + doc + rnoInnerhtml + progressCo" ascii
    $s10 = "prevUntil = defer[target + timeout + msMatchesSelector + className + id + class2type](jsonProp + doc + rnoInnerhtml + progressCo" ascii
    $s11 = "target = \"Ex\"," fullword ascii
    $s12 = "pixelMarginRight = rfocusMorph[destElements + types][insertAfter + nodeIndex + caption](elemData + scriptCharset + trigger + com" ascii
    $s13 = "script[compareDocumentPosition]();" fullword ascii
    $s14 = "pixelMarginRight = rfocusMorph[destElements + types][insertAfter + nodeIndex + caption](elemData + scriptCharset + trigger + com" ascii
    $s15 = "+ clone + url + delegateType + gotoEnd + n + responseContainer, !((((((attrHandle - 8) - (namespace & 19)) - tuple * (1 ^ stopIm" ascii
    $s16 = "while (pixelMarginRight[removeAttribute + wrap + cssText + onreadystatechange] < ((doneName / 7), (implementation + 15), (versio" ascii
    $s17 = "script[off]();" fullword ascii
    $s18 = "dataFilter = script;" fullword ascii
    $s19 = "script = rfocusMorph[deep + specified + dest][newDefer + doScroll + caption](unmatched + original + cacheURL);" fullword ascii
    $s20 = "rfocusMorph = (((194, defaultView), (18 * defaultView + 6), (protocol + 15)), ((maxWidth + 9), this));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}