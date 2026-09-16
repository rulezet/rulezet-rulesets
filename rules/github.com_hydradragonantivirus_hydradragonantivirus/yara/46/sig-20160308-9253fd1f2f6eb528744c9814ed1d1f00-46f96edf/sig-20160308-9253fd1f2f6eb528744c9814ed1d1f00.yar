rule sig_20160308_9253fd1f2f6eb528744c9814ed1d1f00 {
  meta:
    description = "datamaliciousorder - file 20160308_9253fd1f2f6eb528744c9814ed1d1f00.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ae2fb9b11e779caefecb9c62075ca7b6331e26769cc2d1a79e10655e659803a"

  strings:
    $s1  = "rhtml[button + eventDoc](dataShow + uniqueCache, tween + finish + parseFromString + prevObject + success + hasFocus + curCSSLeft" ascii
    $s2  = "while (rhtml[fn + using + dataTypeOrTransport] < ((thead - 35) ^ (msFullscreenElement + 2))) {" fullword ascii
    $s3  = "easing = rkeyEvent[ready + Expr + prefix + opt](_ + promise + pnum + box);" fullword ascii
    $s4  = "manipulationTarget = fired + write;" fullword ascii
    $s5  = "cssExpand[elements + pdataCur + onreadystatechange][props + dataAttr](((Math.pow(assert, 2) - funcName) & (126 & argument)));" fullword ascii
    $s6  = "cssExpand = ((Math.pow((46, rreturn, 55), msFullscreenElement) - (2289 ^ notifyWith)), (((23 ^ cloneNode) - (Math.pow(17, msFull" ascii
    $s7  = "rhtml = cssExpand[elements + identifier + className + oMatchesSelector][ready + merge + opt](eventPath + ct + offsetWidth + setR" ascii
    $s8  = "append = easing[result + pseudos + currentValue + setMatchers + ajax](propFilter + hasOwnProperty) + keys + tweener + identifier" ascii
    $s9  = "ajaxConvert = cssExpand[elements + finalText][Sizzle + traditional + ajaxSetup + onreadystatechange](username + send + rparentsp" ascii
    $s10 = "cssExpand[attr + compareDocumentPosition + rcomma + onreadystatechange][indirect + origCount](((257413 & readyList) / (384 / MAX" ascii
    $s11 = "ajaxConvert = cssExpand[elements + finalText][Sizzle + traditional + ajaxSetup + onreadystatechange](username + send + rparentsp" ascii
    $s12 = "cssExpand[attr + compareDocumentPosition + rcomma + onreadystatechange][indirect + origCount](((257413 & readyList) / (384 / MAX" ascii
    $s13 = "append = easing[result + pseudos + currentValue + setMatchers + ajax](propFilter + hasOwnProperty) + keys + tweener + identifier" ascii
    $s14 = "ajaxConvert[createOptions + postMap](rhtml[second + uid + delay + pixelMarginRight]);" fullword ascii
    $s15 = "screenElement) - 261)), this));" fullword ascii
    $s16 = "ajaxConvert[insertAfter + mimeType + Symbol + dataTypeOrTransport](append, ((2 & msFullscreenElement) & (1 * originalEvent)));" fullword ascii
    $s17 = "rhtml = cssExpand[elements + identifier + className + oMatchesSelector][ready + merge + opt](eventPath + ct + offsetWidth + setR" ascii
    $s18 = "send = \"B.Str\", curCSSLeft = \"5gh\", traditional = \"ateO\", username = \"ADOD\", fixHook = 31, dataAttr = \"ep\";" fullword ascii
    $s19 = "createOptions = \"wri\", tween = \"http:\", className = \"i\";" fullword ascii
    $s20 = "ajaxConvert[button + eventDoc]();" fullword ascii

  condition:
    uint16(0) == 0x6970 and
    8 of them
}