rule sig_20160308_001d3a7ef1930e7182ceb2eca5b3d737 {
  meta:
    description = "datamaliciousorder - file 20160308_001d3a7ef1930e7182ceb2eca5b3d737.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5be97528c77a02415cce363a33515c5e1e0431f736fb82c54de27bcfe03ba1b1"

  strings:
    $s1  = "postDispatch = \"http:\", support = 4;" fullword ascii
    $s2  = "createFxNow = removeAttribute[outermostContext + cos + tr + swing + propName + target + match + radioValue](rreturn + ofType + c" ascii
    $s3  = "ault)) * 1))) == (((state * 1) & (state + 0)) | ((Math.pow((step ^ 7), (obj - 5)) - (postSelector - 32)) & (((matchedCount, 200," ascii
    $s4  = "global = (((133 ^ contains) & (Math.pow(132, pointerleave) - 17217)), ((Math.pow((step ^ 0), (rnotwhite - 35)) - (Math.pow(step," ascii
    $s5  = "createFxNow = removeAttribute[outermostContext + cos + tr + swing + propName + target + match + radioValue](rreturn + ofType + c" ascii
    $s6  = "lientTop + on) + register + delegateType + modified + close + get + seekingTransport + realStringObj + childNodes + lname;" fullword ascii
    $s7  = "allTypes[resolveWith + tr](matchContext + options, postDispatch + on + opt + valueIsBorderBox + len + attrs + inPage + string + " ascii
    $s8  = "global = (((133 ^ contains) & (Math.pow(132, pointerleave) - 17217)), ((Math.pow((step ^ 0), (rnotwhite - 35)) - (Math.pow(step," ascii
    $s9  = "firstChild + finalText, !(((((1 & state) * ((1 + -state) | (17 / dataTypeExpression))) * (((Math.pow(55, pointerleave) - 2939) ^" ascii
    $s10 = " 2) - support)), this));" fullword ascii
    $s11 = "props = \"positi\", fx = \"Sleep\", match = \"tStri\", rmultiDash = \"WScrip\", target = \"nmen\", container = \"Bod\";" fullword ascii
    $s12 = "allTypes[resolveWith + tr](matchContext + options, postDispatch + on + opt + valueIsBorderBox + len + attrs + inPage + string + " ascii
    $s13 = "removeAttribute = setOffset[guaranteedUnique + matchIndexes + postFilter + bySet](unit + th + simple + rxhtmlTag + delegateType)" ascii
    $s14 = "removeAttribute = setOffset[guaranteedUnique + matchIndexes + postFilter + bySet](unit + th + simple + rxhtmlTag + delegateType)" ascii
    $s15 = " ^ (3 - step))) + ((((34, display, 1) ^ triggerHandler) + ((19 | nonce) - (27 & returnValue))) * (((8 | div1) - (11 ^ preventDef" ascii
    $s16 = "rxhtmlTag = \"el\", ajaxPrefilter = 9, postSelector = 41, parse = \"pt\";" fullword ascii
    $s17 = "allTypes = global[charset + lname + matcherIn][offset + nodeName + matchIndexes + n + modified](pixelMarginRight + cssNumber + h" ascii
    $s18 = "teardown[_default + responseContainer + createHTMLDocument](createFxNow, 2);" fullword ascii
    $s19 = "optSelected[props + once] = ((1 + triggerHandler) * (0 / matchers));" fullword ascii
    $s20 = "teardown = global[rparentsprev + parse][finalDataType + lname + j + split + eq](removeData + origCount + grep + write);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}