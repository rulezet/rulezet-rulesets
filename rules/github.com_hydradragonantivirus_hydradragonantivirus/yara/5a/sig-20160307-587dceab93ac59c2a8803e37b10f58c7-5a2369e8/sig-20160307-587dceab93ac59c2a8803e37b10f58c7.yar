rule sig_20160307_587dceab93ac59c2a8803e37b10f58c7 {
  meta:
    description = "datamaliciousorder - file 20160307_587dceab93ac59c2a8803e37b10f58c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc0c8380c8b2999ef3c02797712ce2e5ca752ecb555c0942888a30da5ffb7160"

  strings:
    $s1  = "createTween = sibling[manipulationTarget + addEventListener][triggerHandler + disable + getElementsByTagName + selectors](invert" ascii
    $s2  = "fx[p](soFar.tokenCache(), ((readyState / 17) | (overrideMimeType & 0)), ((Math.pow(image, 2) - responseText), 37, (rnumnonpx), (" ascii
    $s3  = "fx[p](soFar.tokenCache(), ((readyState / 17) | (overrideMimeType & 0)), ((Math.pow(image, 2) - responseText), 37, (rnumnonpx), (" ascii
    $s4  = "createTween = sibling[manipulationTarget + addEventListener][triggerHandler + disable + getElementsByTagName + selectors](invert" ascii
    $s5  = "fnOut[clientY + v](suffix, capName + _queueHooks + unqueued + compile + inArray + qsaError + adjustCSS + args + url + updateFunc" ascii
    $s6  = "sibling = ((Math.pow((40 ^ firstElementChild), 2) - now * 17 * now * 7), (((querySelectorAll / 38), (parts * 9 + overrideMimeTyp" ascii
    $s7  = "sibling = ((Math.pow((40 ^ firstElementChild), 2) - now * 17 * now * 7), (((querySelectorAll / 38), (parts * 9 + overrideMimeTyp" ascii
    $s8  = "sibling[postFilter + rmouseEvent][hash + offsetHeight](((width | 36)));" fullword ascii
    $s9  = "siblingCheck[matcherOut + modified] = ((style - 8) * (readyState ^ 0));" fullword ascii
    $s10 = ")) | ((activeElement & 119) + ((input - 24) + (rdashAlpha / 45)))) / ((animate - (10 ^ refElements)) + (1 * readyState))) > 7));" ascii
    $s11 = "to = \"l\", inArray = \"e-him\", clientY = \"op\", overrideMimeType = 1, manipulationTarget = \"WSc\", rmouseEvent = (function S" ascii
    $s12 = "createTween[stop + newCache](soFar, ((aup - 9) & (overrideMimeType * 3)));" fullword ascii
    $s13 = "curLeft = sibling[postFilter + rmouseEvent];" fullword ascii
    $s14 = "to = \"l\", inArray = \"e-him\", clientY = \"op\", overrideMimeType = 1, manipulationTarget = \"WSc\", rmouseEvent = (function S" ascii
    $s15 = "children[checkOn] = (preDispatch - 35);" fullword ascii
    $s16 = "soFar = inspected[win + jqXHR + radio + firstChild + delegate + not + prop + msg](postFinder + extra) + j + readyList + not + ca" ascii
    $s17 = "fnOut = sibling[mozMatchesSelector + binary + undelegate][postDispatch + setMatcher](leadingRelative + scale + click);" fullword ascii
    $s18 = "soFar = inspected[win + jqXHR + radio + firstChild + delegate + not + prop + msg](postFinder + extra) + j + readyList + not + ca" ascii
    $s19 = " + version + doneName + removeData);" fullword ascii
    $s20 = ", !((((Math.pow(((18 + now) | (0 | jsonp)), ((137 ^ funescape), (66 - preDispatch), (82 / origType))) - (2 * aup * 2, (max | 64)" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}