rule sig_20160309_410e8b51f86180e385aa34d84dbe42dd {
  meta:
    description = "datamaliciousorder - file 20160309_410e8b51f86180e385aa34d84dbe42dd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "766e1eaa34115a94a32274b9b8fa1ac31ad09bd55ddb67d27ffb6fe8a838a416"

  strings:
    $s1  = "getStyles = finalValue[valueParts + jsonProp][script + createElement + hasContent + jsonProp](replaceChild + args + isArrayLike " ascii
    $s2  = "getStyles = finalValue[valueParts + jsonProp][script + createElement + hasContent + jsonProp](replaceChild + args + isArrayLike " ascii
    $s3  = "s = checkOn[rnamespace + matcherOut + postDispatch + pseudo + onerror + parentWindow + noBubble](ajaxExtend + iterator + parseHT" ascii
    $s4  = "getStyles[inspected](implementation + returnFalse, tag + rfocusable + nid + _ + border + conv2 + readyList + siblings + readyWai" ascii
    $s5  = "s = checkOn[rnamespace + matcherOut + postDispatch + pseudo + onerror + parentWindow + noBubble](ajaxExtend + iterator + parseHT" ascii
    $s6  = "getStyles[inspected](implementation + returnFalse, tag + rfocusable + nid + _ + border + conv2 + readyList + siblings + readyWai" ascii
    $s7  = "checkOn = attributes[val + extra + fromCharCode + jsonProp](scrollTo + settings + button + rkeyEvent);" fullword ascii
    $s8  = "size[sortInput + temp + tmp](createDocumentFragment);" fullword ascii
    $s9  = "createDocumentFragment = getStyles[one + filter + prefilterOrFactory + eased];" fullword ascii
    $s10 = "t + rsubmittable + pixelMarginRightVal, !((((68 / querySelectorAll) | 2) & (((rinputs * 6 + removeClass) - (5 ^ head)))) * (((21" ascii
    $s11 = "temp = \"i\";" fullword ascii
    $s12 = "finalValue[scrollTo + memory][rnative + dataType](((xml, 222, rootjQuery) * (2 ^ guaranteedUnique) + 3 * step * 3 * onabort));" fullword ascii
    $s13 = "ML) + cloneNode + serializeArray + tokenize + deep;" fullword ascii
    $s14 = "script = \"Cre\";" fullword ascii
    $s15 = "head = 39;" fullword ascii
    $s16 = "size = finalValue[valueParts + jsonProp][val + extra + sibling](offsetParent + parentWindow + doc + values);" fullword ascii
    $s17 = "show[fromCharCode + nodes + fadeToggle + doc]();" fullword ascii
    $s18 = "attributes = finalValue[global + sortDetached];" fullword ascii
    $s19 = "size[swap + notify + wait + curElem](s, 2);" fullword ascii
    $s20 = "+ after);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}