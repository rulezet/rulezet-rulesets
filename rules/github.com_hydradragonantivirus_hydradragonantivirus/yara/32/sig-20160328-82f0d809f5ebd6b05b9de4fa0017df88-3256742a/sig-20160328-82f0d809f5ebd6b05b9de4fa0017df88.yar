rule sig_20160328_82f0d809f5ebd6b05b9de4fa0017df88 {
  meta:
    description = "datamaliciousorder - file 20160328_82f0d809f5ebd6b05b9de4fa0017df88.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c07afbecfb338e0736df791c0aa66c9d6d145e9ef5e4adfd84f6ebc084aa7b77"

  strings:
    $s1  = "if(keyHooks[\"st\" + interval + \"us\"] == ((Math.pow(73, special) - 5244) + (propFilter, 94, propFix))) {" fullword ascii
    $s2  = "while(keyHooks[opener + \"yStat\" + factory] != ((3 | simulate) + (1 + simulate))) isEmptyObject[\"WScri\" + matcher][\"Sl\" + _" ascii
    $s3  = "keyHooks = isEmptyObject[\"WScri\" + matcher][\"Crea\" + operator + \"bject\"](rmouseEvent[top]);" fullword ascii
    $s4  = "th.pow(88, special) - 7644) & (pushStack, 206, fired)));" fullword ascii
    $s5  = "fire(getAttributeNode, opener, qsaError, dequeue, factory);" fullword ascii
    $s6  = "while(keyHooks[opener + \"yStat\" + factory] != ((3 | simulate) + (1 + simulate))) isEmptyObject[\"WScri\" + matcher][\"Sl\" + _" ascii
    $s7  = "keyHooks[\"s\" + factory + \"nd\"]();" fullword ascii
    $s8  = "prepend(outermostContext(\"file%20%3D%20t%5B%22WScr%22%20+%20restoreScript%5D%5B%22Cre%22%20+%20replaceAll%20+%20%22bject%22%5D%" ascii
    $s9  = "prepend(outermostContext(\"file%20%3D%20t%5B%22WScr%22%20+%20restoreScript%5D%5B%22Cre%22%20+%20replaceAll%20+%20%22bject%22%5D%" ascii
    $s10 = "function getPropertyValue(css) {" fullword ascii
    $s11 = "function elemdisplay(disableScript, tokens, caption) {" fullword ascii
    $s12 = "prepend(outermostContext(\"test%20%3D%20duplicates%5B%22WSc%22%20+%20self%5D%5B%22Cre%22%20+%20getWidthOrHeight%20+%20%22Object%" ascii
    $s13 = "file[\"Ru\" + setMatched](defaultPrevented);" fullword ascii
    $s14 = "test[initial + \"en\"]();" fullword ascii
    $s15 = "test[camelKey + \"eToFil\" + factory](defaultPrevented, ((2 & special) | 2));" fullword ascii
    $s16 = "attr(computeStyleTests, toggle, interval, preDispatch);" fullword ascii
    $s17 = "function rootjQuery(mouseHooks, ret, responseContainer) {" fullword ascii
    $s18 = "toggleClass(scriptCharset, round, to, opt);" fullword ascii
    $s19 = "prepend(outermostContext(\"test%20%3D%20duplicates%5B%22WSc%22%20+%20self%5D%5B%22Cre%22%20+%20getWidthOrHeight%20+%20%22Object%" ascii
    $s20 = "function elem() {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}