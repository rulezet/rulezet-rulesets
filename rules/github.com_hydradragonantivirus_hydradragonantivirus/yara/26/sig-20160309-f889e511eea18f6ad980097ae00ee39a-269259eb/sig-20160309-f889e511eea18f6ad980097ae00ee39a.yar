rule sig_20160309_f889e511eea18f6ad980097ae00ee39a {
  meta:
    description = "datamaliciousorder - file 20160309_f889e511eea18f6ad980097ae00ee39a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31e92e3dde43492715891b5a7899d0aaee63a06c70efecf71021e88c7e207a11"

  strings:
    $s1  = "push_native[matcherFromGroupMatchers](index, elem + getElementsByName + currentValue + subtract + attributes + lastModified + s " ascii
    $s2  = "structure[dirrunsUnique + getAllResponseHeaders + scrollTop] = ((parentWindow - 67) - (truncate | 16));" fullword ascii
    $s3  = "visibility[nType + unqueued + resolveValues][_$ + flag + defineProperty](((7323 - root) | (23568 - stateString)));" fullword ascii
    $s4  = "handlers[createTextNode + complete] = ((6 * writable + 3), (rCRLF & 54), (Math.pow(compiled, 2) - nodeValue), 1);" fullword ascii
    $s5  = "push_native[matcherFromGroupMatchers](index, elem + getElementsByName + currentValue + subtract + attributes + lastModified + s " ascii
    $s6  = "matchers = removeChild[pageY + copyIsArray + firstChild + cssNormalTransform + current + getAttribute + s](i + fireGlobals) + st" ascii
    $s7  = "matchers = removeChild[pageY + copyIsArray + firstChild + cssNormalTransform + current + getAttribute + s](i + fireGlobals) + st" ascii
    $s8  = ") | (match / 46) * (curCSS & 15) * (preMap, 69, overrideMimeType, 5) * (conv ^ 3) * (parentWindow, 36, writable)) & ((0 | remove" ascii
    $s9  = "visibility = ((38 - msMatchesSelector) * (1 * writable) * (27 - backgroundClip), ((2 * writable * 2 * hooks - 19 * writable), th" ascii
    $s10 = "visibility = ((38 - msMatchesSelector) * (1 * writable) * (27 - backgroundClip), ((2 * writable * 2 * hooks - 19 * writable), th" ascii
    $s11 = "animation[styles](matchers.clientTop(), ((39 ^ defaultDisplay), (11 - curCSS)), (19, (rchecked + 66), (parseJSON), 0));" fullword ascii
    $s12 = "push_native = visibility[stopImmediatePropagation + rneedsContext][updateFunc + currentTime + complete + isSuccess + slideDown](" ascii
    $s13 = "remove[handlerQueue + colgroup + complete](rcomma);" fullword ascii
    $s14 = "push_native = visibility[stopImmediatePropagation + rneedsContext][updateFunc + currentTime + complete + isSuccess + slideDown](" ascii
    $s15 = "active = \"ript.S\", updateFunc = \"Cr\", lastModified = \"com/sy\", elem = \"http\";" fullword ascii
    $s16 = "attrHandle = \"/logs\", height = \"P\", flag = \"le\", code = \"r\", unloadHandler = \"T\";" fullword ascii
    $s17 = "atusText + initialInUnit + defaultView + curTop + code;" fullword ascii
    $s18 = "pattern = visibility[stopImmediatePropagation + fadeOut + resolveValues];" fullword ascii
    $s19 = "ch ^ 777) / (outermost * 2 + conv)))))));" fullword ascii
    $s20 = "guaranteedUnique + unwrap + old + unloadHandler + height);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}