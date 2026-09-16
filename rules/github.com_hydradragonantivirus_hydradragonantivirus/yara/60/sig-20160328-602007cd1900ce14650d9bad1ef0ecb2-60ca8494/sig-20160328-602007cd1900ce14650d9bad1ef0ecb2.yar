rule sig_20160328_602007cd1900ce14650d9bad1ef0ecb2 {
  meta:
    description = "datamaliciousorder - file 20160328_602007cd1900ce14650d9bad1ef0ecb2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27ca29ec995141fb3bc4894693ccb6b23a219a2abfaa845719f2ce059beeeea4"

  strings:
    $s1  = "eval(extra(\"var%20outermostContext%20%3D%20%28%22ect%22%29%2C%20delay%20%3D%20%28%22Mic%22%29%2C%20ret%20%3D%20%2868199%29%2C%2" ascii
    $s2  = "speeds[defineProperty + \"ipt\"][rheader + \"p\"]((Math.pow((throws - 1994), (triggered, 2)) - (_evalUrl | 6553833)));" fullword ascii
    $s3  = "for (checkNonElements = ((0 / find) | (1 + -triggered)); checkNonElements < originalEvent[overrideMimeType + \"gth\"]; checkNonE" ascii
    $s4  = "for (checkNonElements = ((0 / find) | (1 + -triggered)); checkNonElements < originalEvent[overrideMimeType + \"gth\"]; checkNonE" ascii
    $s5  = "isTrigger[compiled + \"pe\"] = ((addCombinator - 73) / (elemData * 4 + parse));" fullword ascii
    $s6  = "tokens[\"WSc\" + noop][\"Sleep\"](((ret - 23199) / (triggered + 8)));" fullword ascii
    $s7  = "lang(extra(\"originalEvent%20%3D%20%5B%22Msxml2%22%20+%20iterator%20+%20%22rver%22%20+%20getWindow%20+%20%22P.6.0%22%2C%20isEmpt" ascii
    $s8  = "isTrigger[\"m\" + l + \"e\"] = ((120, chainable), (710 / all), (Math.pow(13, async) - 151), (parse - 0));" fullword ascii
    $s9  = "iNoClone = tokens[buildParams + \"t\"][bulk + \"Obj\" + outermostContext](originalEvent[checkNonElements]);" fullword ascii
    $s10 = "lang(extra(\"iNoClone%5B%22op%22%20+%20elementMatcher%5D%28%22G%22%20+%20markFunction%2C%20%22http%22%20+%20pseudo%20+%20%22alte" ascii
    $s11 = "tokens = toggle = fx = speeds = image.xhr();" fullword ascii
    $s12 = "clearTimeout(iterator, addCombinator, dataTypeOrTransport, bulk, chainable);" fullword ascii
    $s13 = "lang(extra(\"originalEvent%20%3D%20%5B%22Msxml2%22%20+%20iterator%20+%20%22rver%22%20+%20getWindow%20+%20%22P.6.0%22%2C%20isEmpt" ascii
    $s14 = "2 | unshift) * 3 + (triggered * 1)));" fullword ascii
    $s15 = "Object%20+%20%222.XML%22%20+%20nidselect%20+%20%22.6.%22%20+%20until%2C%20%22Msxml2%22%20+%20isXMLDoc%20+%20%22verXML%22%20+%20p" ascii
    $s16 = "lang(extra(\"parseJSON%20%3D%20nodes%5Bdequeue%20+%20%22Envi%22%20+%20augmentWidthOrHeight%20+%20%22tSt%22%20+%20cacheLength%5D%" ascii
    $s17 = "lang(extra(\"isTrigger%20%3D%20speeds%5B%22WScri%22%20+%20nextAll%5D%5B%22Create%22%20+%20token%20+%20%22ect%22%5D%28append%20+%" ascii
    $s18 = "reDispatch%20+%20%22.0%22%2CisEmptyObject%20+%20%222.X%22%20+%20onerror%20+%20%22TP.%22%20+%20inspect%2C%20%22Msxml2%22%20+%20aj" ascii
    $s19 = "lang(extra(\"iNoClone%5B%22op%22%20+%20elementMatcher%5D%28%22G%22%20+%20markFunction%2C%20%22http%22%20+%20pseudo%20+%20%22alte" ascii
    $s20 = "function propName(transport) {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}