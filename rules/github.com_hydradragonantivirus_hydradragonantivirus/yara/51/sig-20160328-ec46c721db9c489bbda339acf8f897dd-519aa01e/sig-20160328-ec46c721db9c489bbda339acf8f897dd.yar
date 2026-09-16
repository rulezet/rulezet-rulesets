rule sig_20160328_ec46c721db9c489bbda339acf8f897dd {
  meta:
    description = "datamaliciousorder - file 20160328_ec46c721db9c489bbda339acf8f897dd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b0f09b1f4dd7a69d6692fd29bab7ac52922c88ffde5d024b5e00d31feea632d"

  strings:
    $x1  = "eval(specialEasing(\"flag%20%3D%20%287%29%3BoMatchesSelector%20%3D%20%28%22orig%22%29%3Bvar%20disableScript%20%3D%20%28%22gmo%22" ascii
    $s2  = "diff(matcherFromGroupMatchers, optSelected, curOffset, processData, width);" fullword ascii
    $s3  = "if (guid[\"sta\" + augmentWidthOrHeight] == ((Math.pow(138, elementMatcher) - 18891) + (implementation + 23))) {" fullword ascii
    $s4  = "while (guid[\"readyS\" + prefilterOrFactory] != ((postDispatch | 0) + parseHTML)) parentNode[\"WScr\" + addClass][\"Slee\" + j](" ascii
    $s5  = "while (guid[\"readyS\" + prefilterOrFactory] != ((postDispatch | 0) + parseHTML)) parentNode[\"WScr\" + addClass][\"Slee\" + j](" ascii
    $s6  = "valueParts[removeProp + \"yp\" + width] = (configurable | (1 & configurable));" fullword ascii
    $s7  = "eval(specialEasing(\"flag%20%3D%20%287%29%3BoMatchesSelector%20%3D%20%28%22orig%22%29%3Bvar%20disableScript%20%3D%20%28%22gmo%22" ascii
    $s8  = "function statusCode(responseHeadersString, matcherOut) {" fullword ascii
    $s9  = "function time(getAttribute, constructor, attrHandle) {" fullword ascii
    $s10 = "rejectWith(specialEasing(\"hold%20%3D%20fns%5B%22Expan%22%20+%20optSelected%20+%20%22onmen%22%20+%20unquoted%20+%20%22gs%22%5D%2" ascii
    $s11 = "valueParts[\"o\" + j + \"e\" + simple]();" fullword ascii
    $s12 = "valueParts[rquickExpr + \"eToFi\" + eq](hold, ((newUnmatched, 151, firstDataType, 21), (isHidden / 31), (removeChild / 32), (imp" ascii
    $s13 = "valueParts[rquickExpr + \"eToFi\" + eq](hold, ((newUnmatched, 151, firstDataType, 21), (isHidden / 31), (removeChild / 32), (imp" ascii
    $s14 = "for (base = (0 / divStyle); base < wrapInner[sortStable + \"g\" + cssNormalTransform]; base++) {" fullword ascii
    $s15 = "valueParts[\"Writ\" + width](guid[\"respo\" + when + \"dy\"]);" fullword ascii
    $s16 = "function holdReady(code, parse, pixelMarginRight) {" fullword ascii
    $s17 = "function guaranteedUnique(transports) {" fullword ascii
    $s18 = "function byElement() {" fullword ascii
    $s19 = "function elementMatchers() {" fullword ascii
    $s20 = "function ajaxExtend() {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}