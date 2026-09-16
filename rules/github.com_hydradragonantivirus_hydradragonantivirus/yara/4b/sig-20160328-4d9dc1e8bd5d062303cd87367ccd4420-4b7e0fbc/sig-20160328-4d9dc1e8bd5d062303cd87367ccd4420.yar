rule sig_20160328_4d9dc1e8bd5d062303cd87367ccd4420 {
  meta:
    description = "datamaliciousorder - file 20160328_4d9dc1e8bd5d062303cd87367ccd4420.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6685a62f56178baa367e131e6547a90a8d10400df802a7ebb75a41d65be3537f"

  strings:
    $s1  = "    while(nodeValue[\"read\" + prevUntil + \"ate\"] != ((fadeOut - 6) & (Math.pow(sortDetached, 2) - func))) until[bubbleType + " ascii
    $s2  = "relative(rheader, pipe, a, nextSibling);" fullword ascii
    $s3  = "until = hasContent = requestHeadersNames = cur = num.onload();" fullword ascii
    $s4  = "    while(nodeValue[\"read\" + prevUntil + \"ate\"] != ((fadeOut - 6) & (Math.pow(sortDetached, 2) - func))) until[bubbleType + " ascii
    $s5  = "function getAttributeNode(settings, computed) {" fullword ascii
    $s6  = "][param + \"eep\"](((15 + left) | (1044 / binary)));" fullword ascii
    $s7  = "    for(hidden = (dataTypes * (1 * onreadystatechange)); hidden < pixelMarginRightVal[originalProperties + \"ng\" + pointerenter" ascii
    $s8  = "    for(hidden = (dataTypes * (1 * onreadystatechange)); hidden < pixelMarginRightVal[originalProperties + \"ng\" + pointerenter" ascii
    $s9  = "    if(nodeValue[matcher] == (2 * (detach / 6) * (pipe, 225, func) * 2 * (a + 0))) {" fullword ascii
    $s10 = "function relative(copy, postFinder, rdisplayswap) {" fullword ascii
    $s11 = "getAttributeNode(boxSizingReliableVal, dataAttr, reject, assert, detach);" fullword ascii
    $s12 = "activeElement[\"mo\" + fcamelCase] = ((2 * a * 2) - (empty / 39));" fullword ascii
    $s13 = "        activeElement[\"Wri\" + boxSizingReliableVal](nodeValue[\"respo\" + forward + \"Body\"]);" fullword ascii
    $s14 = "activeElement[\"t\" + elems + \"e\"] = ((checked / 25) / (reject & 55));" fullword ascii
    $s15 = "function inspected(rrun, dataFilter, dequeue) {" fullword ascii
    $s16 = "function fireWith(iframe) {" fullword ascii
    $s17 = "subtract();" fullword ascii
    $s18 = "function global(handlerQueue) {" fullword ascii
    $s19 = "clone%2C128%2Ctr%29%29%20%3E%201%29%29%3B\"));" fullword ascii
    $s20 = "function jsonProp(response) {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}