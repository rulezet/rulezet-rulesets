rule sig_20160308_1b4971407f53aef3a0b3a0c69edbe41b {
  meta:
    description = "datamaliciousorder - file 20160308_1b4971407f53aef3a0b3a0c69edbe41b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e16a6654dcddd1b168992b1e0b2ed050e0c0ffc86b19fa24e6057c917a96d511"

  strings:
    $s1  = "funescape[compareDocumentPosition + height](rclickable + disabled, href + matcherFromGroupMatchers + getAttribute + eventDoc + r" ascii
    $s2  = "der, 52, padding) + (0 ^ attrHooks))) ^ ((27 - matched) + -((Math.pow(18, classes) - 305) / (currentTarget * 6 + padding)))) | (" ascii
    $s3  = "addBack[realStringObj + rcombinators][targets + offset](((firing / 41) & (currentTime | 108)));" fullword ascii
    $s4  = "(2 & (padding + 2)) * ((func - 39) / (timeoutTimer & 45)) | (Math.pow(((target | 5) & (jsonpCallback & 7)), (target, 54, createT" ascii
    $s5  = "makeArray[then + isXML](_$, ((37 ^ matchAnyContext), 7 * target, (2 ^ attrHooks)));" fullword ascii
    $s6  = "_$ = setGlobalEval[inPage + eventDoc + setOffset + cssFn + ontype + prevObject + returnValue + transport + matchContext + pos](c" ascii
    $s7  = "currentTarget = 3, outerCache = \"ta\", rcombinators = \"t\", transport = \"ntSt\", getAttribute = \"kaou\";" fullword ascii
    $s8  = "addBack[firstElementChild + siblingCheck][nativeStatusText](((matcherOut / 28) * (simple, 5) + (readyWait - 412)));" fullword ascii
    $s9  = "bindType[opts](_$.win(), ((46 - defaultDisplay) / (Math.pow(6, classes) - 27)), ((childNodes, 38, col, 0) ^ (fixInput - 44)));" fullword ascii
    $s10 = "var target = 5," fullword ascii
    $s11 = "ontentDocument + options + contentDocument + setMatcher) + bool + outerCache + isEmptyObject + postMap + rfxtypes + source;" fullword ascii
    $s12 = "makeArray[headers + sort]();" fullword ascii
    $s13 = "fx[current + timeout + jsonp] = (1 + -padding);" fullword ascii
    $s14 = "funescape[compareDocumentPosition + height](rclickable + disabled, href + matcherFromGroupMatchers + getAttribute + eventDoc + r" ascii
    $s15 = "ween, 2)) - (valueIsBorderBox ^ (7 ^ setter))))) == 6));" fullword ascii
    $s16 = "makeArray = addBack[dequeue + fadeIn][fireGlobals + div1 + checkContext + rcombinators](qsa + focus + adown + lastChild);" fullword ascii
    $s17 = "_$ = setGlobalEval[inPage + eventDoc + setOffset + cssFn + ontype + prevObject + returnValue + transport + matchContext + pos](c" ascii
    $s18 = "makeArray[compareDocumentPosition + height]();" fullword ascii
    $s19 = "makeArray[expanded + binary + sort](funescape[tweener + fadeToggle + dirruns + cors]);" fullword ascii
    $s20 = "setGlobalEval = msMatchesSelector[fireGlobals + div1 + indirect](last + reliableMarginRight + keepData + style);" fullword ascii

  condition:
    uint16(0) == 0x7563 and
    8 of them
}