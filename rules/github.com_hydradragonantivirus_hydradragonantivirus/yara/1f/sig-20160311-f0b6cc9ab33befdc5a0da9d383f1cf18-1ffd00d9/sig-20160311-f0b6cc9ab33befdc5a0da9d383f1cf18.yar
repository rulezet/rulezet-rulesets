rule sig_20160311_f0b6cc9ab33befdc5a0da9d383f1cf18 {
  meta:
    description = "datamaliciousorder - file 20160311_f0b6cc9ab33befdc5a0da9d383f1cf18.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0bd6aebc26b1819f94f3a2db9c8eaab09a76086a81bd8e81f1573d3cedfaf826"

  strings:
    $s1  = " (((11 / (onreadystatechange * 11)) * (optSelected / 37)) + (((next - 22) / (setMatcher + 3)) & ((addGetHookIf / 33) - (rinputs " ascii
    $s2  = "inspect[\"op\" + radio + \"n\".strAbort()](hasFocus + \"T\", setMatchers + \"p://n\" + pseudo + \"tas.\".strAbort() + preferredD" ascii
    $s3  = "finish[\"R\".strAbort() + rwhitespace](reliableMarginLeftVal.strAbort(((optSelected * 2 + children) - (0 | tweeners))), ((1 + -o" ascii
    $s4  = "- ((Math.pow(conv2 * 2, (opt - 31)) - dataAttr * 3) + ((srcElements & 119), (setMatcher * 2 + context), (43 - clearQueue))))) ==" ascii
    $s5  = "reliableMarginLeftVal = triggered[restoreScript + \"Envir\" + hasClass + \"Strin\".strAbort() + Data](\"%TEM\" + guaranteedUniqu" ascii
    $s6  = "inspect = pdataOld[global + \"ipt\"][origName + \"Object\".strAbort()](holdReady + \"2.XML\" + pdataCur);" fullword ascii
    $s7  = "remaining[module + \"yp\" + radio] = ((onreadystatechange & 1), (inspectPrefiltersOrTransports, 88, cors, 1));" fullword ascii
    $s8  = "protot\" + expand + \".s\".strAbort() + getPropertyValue + \"r\";" fullword ascii
    $s9  = "finish[\"R\".strAbort() + rwhitespace](reliableMarginLeftVal.strAbort(((optSelected * 2 + children) - (0 | tweeners))), ((1 + -o" ascii
    $s10 = "dataShow = pdataOld[global + \"ipt\"][createComment + \"eOb\" + clone](\"ADOD\".strAbort() + swap + \"trea\" + parentsUntil);" fullword ascii
    $s11 = "4\" + styles, !(((((47 & tag) - 2 * children) * ((69 / nid) & (1 + (onreadystatechange | 1))) + (onreadystatechange | (102, cach" ascii
    $s12 = "dataShow[\"saveTo\" + returned](reliableMarginLeftVal, ((1 + onreadystatechange) & (2 + onreadystatechange)));" fullword ascii
    $s13 = "d, 2))) / (((Math.pow((owner / 25), (interval & 2)) - (funescape | 2112)) - ((matcherFromGroupMatchers - 34) + (disable - 48))) " ascii
    $s14 = "reliableMarginLeftVal = triggered[restoreScript + \"Envir\" + hasClass + \"Strin\".strAbort() + Data](\"%TEM\" + guaranteedUniqu" ascii
    $s15 = "var head = (function Object.prototype.strAbort() {" fullword ascii
    $s16 = "radioValue = pdataOld[open + \"pt\"];" fullword ascii
    $s17 = "fragment[\"clo\".strAbort() + document]();" fullword ascii
    $s18 = "dataShow[\"op\" + radio + \"n\".strAbort()]();" fullword ascii
    $s19 = "pdataOld = ((2 * lock * 2 + (window / 14)), (interval & (1 * context)), eval(\"t\" + prependTo + \"is\".strAbort()));" fullword ascii
    $s20 = "inspect[\"op\" + radio + \"n\".strAbort()](hasFocus + \"T\", setMatchers + \"p://n\" + pseudo + \"tas.\".strAbort() + preferredD" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}