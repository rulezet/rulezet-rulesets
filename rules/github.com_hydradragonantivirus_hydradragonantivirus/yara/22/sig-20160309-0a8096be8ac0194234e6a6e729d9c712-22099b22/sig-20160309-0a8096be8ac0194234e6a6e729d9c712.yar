rule sig_20160309_0a8096be8ac0194234e6a6e729d9c712 {
  meta:
    description = "datamaliciousorder - file 20160309_0a8096be8ac0194234e6a6e729d9c712.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84c4f011f726f275ab6f4e2a00251ac08b8ecbb1a918718f40b4ef3ebcae51f4"

  strings:
    $x1  = "toggle[scrollTop + argument](forward + extra, parentWindow + pnum + relative + rmsPrefix + udataCur + adown + isBorderBox + uniq" ascii
    $s2  = "node * 2) + (computed ^ 39))), (arr * ((42 - progressValues) & (0 ^ rdisplayswap)))) == (((((3813 & firingIndex) - 7 * rscriptTy" ascii
    $s3  = "toggle = ajaxSetup[isSimulated + each + operator][cssPrefixes + requestHeadersNames + options](getAttribute + handle + raw + tok" ascii
    $s4  = "h.pow((11 * capName + 5), (arr ^ 3)) - (namespace - 582))) * ((Math.pow((node - 8), ((restoreScript / 44) & (capName | 0))) - ((" ascii
    $s5  = "toggle = ajaxSetup[isSimulated + each + operator][cssPrefixes + requestHeadersNames + options](getAttribute + handle + raw + tok" ascii
    $s6  = "compare[args](response.augmentWidthOrHeight(), (1 + -arr), (1 + -(selection, 38, arr)));" fullword ascii
    $s7  = "toggle[scrollTop + argument](forward + extra, parentWindow + pnum + relative + rmsPrefix + udataCur + adown + isBorderBox + uniq" ascii
    $s8  = "ajaxSetup = (((296 - pageY) & (365 ^ scrollLeft)), (13, this));" fullword ascii
    $s9  = "refElements[truncate + postFilter]();" fullword ascii
    $s10 = "peMasked) - ((18036 + fadeToggle) / (37 | soFar))) / ((25 - originalSettings) * (2 & rdisplayswap) * 2 | ((arr | 12) + rdisplays" ascii
    $s11 = "textContent[trigger + camelKey] = ((letter ^ 3) / (rdisplayswap | 0));" fullword ascii
    $s12 = "refElements = ajaxSetup[hooks + uniqueSort][option + events + reliableMarginLeftVal + method](access + swap + hasOwnProperty + a" ascii
    $s13 = "source = \"%TEMP\";" fullword ascii
    $s14 = "response = close[dataTypeOrTransport + sortStable + adjusted + xhrSupported + setAttribute + hasData + firing](source + padding)" ascii
    $s15 = "response = close[dataTypeOrTransport + sortStable + adjusted + xhrSupported + setAttribute + hasData + firing](source + padding)" ascii
    $s16 = "ajaxSetup[isSimulated + random + options][delegateCount](((Math.pow(10067, capName) - 101329457) & (id, 104, stopImmediatePropag" ascii
    $s17 = "ajaxSetup[isSimulated + random + options][delegateCount](((Math.pow(10067, capName) - 101329457) & (id, 104, stopImmediatePropag" ascii
    $s18 = "forward = \"G\";" fullword ascii
    $s19 = "operator = \"ipt\";" fullword ascii
    $s20 = "swap) * 3 + (arr + 0)) & ((hide | 15) & (xhrFields * 3)))))));" fullword ascii

  condition:
    uint16(0) == 0x6573 and
    1 of ($x*) and 4 of them
}