rule sig_20160307_f8b2ed260efa93b1af8230e421b2ee64 {
  meta:
    description = "datamaliciousorder - file 20160307_f8b2ed260efa93b1af8230e421b2ee64.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d1c38910d0bc3956c5e03ba0f73a9dc5d52211530dfb1f0e4d237b2f5dffe2d"

  strings:
    $s1  = "td[lname + rsubmittable + using](high, stateVal + complete + container + rdashAlpha + rtagName + postSelector + hasOwnProperty +" ascii
    $s2  = "ool * 2))))) == ((((elemdisplay * 2 * implementation * 2 - (abort / 7)) * (elemdisplay / 1) + (rscriptTypeMasked & 3)) - (((remo" ascii
    $s3  = "createTextNode[pseudos + camelCase + root][marginLeft]((0 | state) * (4 ^ bool) * (2 | rscriptTypeMasked) * (Math.pow(4, elemdis" ascii
    $s4  = "guaranteedUnique[dataAttr] = ((getter - 11) | (unqueued / 34));" fullword ascii
    $s5  = "Cache)) / ((374 / styles) | (Math.pow(9, elemdisplay) - 64))), (((Math.pow(getter, 2) - rescape) - 16) * ((removeEvent | 0) ^ (b" ascii
    $s6  = "td = createTextNode[needsContext + root][then + opts + get](pageX + values + animated + origCount + maxIterations);" fullword ascii
    $s7  = "td[lname + rsubmittable + using](high, stateVal + complete + container + rdashAlpha + rtagName + postSelector + hasOwnProperty +" ascii
    $s8  = "conditionFn = divStyle[owner + hasData + padding + operator + createOptions + rnotwhite](removeAttribute + webkitMatchesSelector" ascii
    $s9  = "veEvent ^ 0) ^ (andSelf ^ 15)) + ((Math.pow(stopImmediatePropagation, 2) - parentWindow) / (8 | styles)))) + (((0 / list) & (1 |" ascii
    $s10 = "pipe = createTextNode[getElementsByName + preFilter][remaining + rcomma + completed + rjsonp + obj](getElementsByClassName + get" ascii
    $s11 = "pipe = createTextNode[getElementsByName + preFilter][remaining + rcomma + completed + rjsonp + obj](getElementsByClassName + get" ascii
    $s12 = "setGlobalEval[Data + setPositiveNumber + using] = ((genFx - 43) / (Math.pow(list, 2) - now));" fullword ascii
    $s13 = "pipe[accepts](td[cos + createElement + attr + name]);" fullword ascii
    $s14 = "createTextNode[prevAll + includeWidth][pixelPositionVal + jsonp](((implementation * 12 + rscriptTypeMasked) ^ (7 ^ xhrFields)));" ascii
    $s15 = "pipe[nodeIndex + handle]();" fullword ascii
    $s16 = "pipe[elementMatcher + fn + documentIsHTML](conditionFn, (44 / styles));" fullword ascii
    $s17 = " rscriptTypeMasked)), (((19 * rscriptTypeMasked + 7) * (offset, 154, rscriptTypeMasked) + (6 + compilerCache)), ((8184 & eventDo" ascii
    $s18 = "createTextNode[pseudos + camelCase + root][marginLeft]((0 | state) * (4 ^ bool) * (2 | rscriptTypeMasked) * (Math.pow(4, elemdis" ascii
    $s19 = "conditionFn = divStyle[owner + hasData + padding + operator + createOptions + rnotwhite](removeAttribute + webkitMatchesSelector" ascii
    $s20 = "play) - 11) * elemdisplay * 2 * (elemdisplay ^ 0) * (delegateCount + 1));" fullword ascii

  condition:
    uint16(0) == 0x6874 and
    8 of them
}