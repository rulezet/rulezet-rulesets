rule sig_20160307_ef53b881cbd469a48403c12676a18020 {
  meta:
    description = "datamaliciousorder - file 20160307_ef53b881cbd469a48403c12676a18020.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23b7b837d80ccd8776a7e8663a99d1cd59ad45a0101a6d9c91e58993b6fb4cf7"

  strings:
    $s1  = "curValue[attrHandle + left](firingIndex + hooks, timer + tag + unbind + unqueued + last + matcherIn + script + support + curElem" ascii
    $s2  = "responseType[disableScript + augmentWidthOrHeight] = ((textContent | 240), (PI - 178), (defineProperty / 15), handle);" fullword ascii
    $s3  = " + options + ajaxTransport, !((((((470 / charCode) & (12 | getJSON)) + ((1 | handle) * (6 + propName))) / (((72 + nextSibling) -" ascii
    $s4  = "curValue[attrHandle + left](firingIndex + hooks, timer + tag + unbind + unqueued + last + matcherIn + script + support + curElem" ascii
    $s5  = "SizingReliableVal ^ 47)))) * ((((Math.pow(combinator, 2) - nonce) | (4488 / matchExpr)) & ((4 & focusin) | (223 & stored))), (((" ascii
    $s6  = "trigger[easing + sortDetached] = ((1 + compiled) + -(0 | handle));" fullword ascii
    $s7  = "responseText[readyList](camel.contentType(), ((59, clientY, 0) | (compiled / 19)), ((handle * 1) * compiled));" fullword ascii
    $s8  = "textContent = 178, multipleContexts = \"ysta\", script = \"sapo\", opt = \"onseBo\", nextSibling = 30, createInputPseudo = \"Cr" ascii
    $s9  = "v = rcomma[createInputPseudo + tuple + keyHooks + bubbleType](handler + pop + groups);" fullword ascii
    $s10 = "camel = v[parseXML + fcamelCase + teardown + left + old + handleObj + fadeToggle + relatedTarget + finish](select + find + rdash" ascii
    $s11 = "camel = v[parseXML + fcamelCase + teardown + left + old + handleObj + fadeToggle + relatedTarget + finish](select + find + rdash" ascii
    $s12 = "boxSizingReliable[memory + restoreScript + raw](camel, ((225, reliableMarginLeftVal) / (41 - parts)));" fullword ascii
    $s13 = "createTextNode = (((114 + classCache) - (71 + getText)), (((6 + rCRLF) * (2 & boxSizingReliableVal)), this));" fullword ascii
    $s14 = "completed = (function String.prototype.contentType() {" fullword ascii
    $s15 = "createTextNode[copy + hasClass + postDispatch + curElem][rclass](((65 + reverse), (95 * rCRLF + 13), (optgroup / 44), (completed" ascii
    $s16 = "createTextNode[copy + hasClass + postDispatch + curElem][rclass](((65 + reverse), (95 * rCRLF + 13), (optgroup / 44), (completed" ascii
    $s17 = "230 - submit) + (Math.pow(39, rCRLF) - 1465)) & ((rnumnonpx * 2 + returnValue) & (Math.pow(101, rCRLF) - 10010))), (((response -" ascii
    $s18 = "copy = \"WS\", preFilter = \".scr\";" fullword ascii
    $s19 = "deep = \"WSc\", getJSON = 80, hooks = \"ET\", memory = \"sa\", parts = 12, raw = \"ile\";" fullword ascii
    $s20 = "boxSizingReliable = createTextNode[deep + reset + tweener + ajax][stopQueue + allTypes](attrNames + rnative + fxNow);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}