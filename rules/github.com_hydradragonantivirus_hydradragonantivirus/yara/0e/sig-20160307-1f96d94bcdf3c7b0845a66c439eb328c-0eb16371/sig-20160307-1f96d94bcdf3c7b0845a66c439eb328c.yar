rule sig_20160307_1f96d94bcdf3c7b0845a66c439eb328c {
  meta:
    description = "datamaliciousorder - file 20160307_1f96d94bcdf3c7b0845a66c439eb328c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbd31e4ef786c124b58ebd787c2a5488056db10df19ed19808f6f8e2daa8fcff"

  strings:
    $s1  = "rcleanScript[attachEvent](a.unqueued(), (rtrim + -1), (checkNonElements * 3 * checkNonElements - (22 + content)));" fullword ascii
    $s2  = "onload = ((0 | reliableMarginLeftVal) * (2 * fadeTo + 1), (((blur / 18), content * 3, (iNoClone / 38), (Math.pow(currentValue, 2" ascii
    $s3  = "a = tbody[stopQueue + fnOver + active + stop + rdashAlpha + risSimple + onreadystatechange](responseContainer + whitespace + wra" ascii
    $s4  = "pInner) + keyCode + rkeyEvent + postMap + vendorPropName + dataAttr + cached;" fullword ascii
    $s5  = "isTrigger[mozMatchesSelector + visibility](a, ((28 - get) ^ 2));" fullword ascii
    $s6  = "onload = ((0 | reliableMarginLeftVal) * (2 * fadeTo + 1), (((blur / 18), content * 3, (iNoClone / 38), (Math.pow(currentValue, 2" ascii
    $s7  = "To), 11 * fadeTo) & (Math.pow((11 * fadeTo + 3), fadeTo) - (173 ^ letter)))) - ((((1 & rtrim) & (1 & rtrim)) * (3 | (elementMatc" ascii
    $s8  = "unit[send](td, name + collection + chainable + e + mouseenter + tokenCache + _default + documentElement + clearCloneStyle, !((((" ascii
    $s9  = "hers | 4))) * (((_ - 43) & (rtrim * 2)) ^ ((noBubble & 1))))) == fadeTo));" fullword ascii
    $s10 = "siblingCheck = \"Cr\", content = 5, onreadystatechange = \"ngs\", clearCloneStyle = \"bd23\", iterator = \"WS\";" fullword ascii
    $s11 = "while(unit[one + ajaxPrefilter + booleans + wrapAll + rwhitespace] < ((1 + -rtrim) | (54 - pageYOffset))) {" fullword ascii
    $s12 = ") - m)), this));" fullword ascii
    $s13 = "a = tbody[stopQueue + fnOver + active + stop + rdashAlpha + risSimple + onreadystatechange](responseContainer + whitespace + wra" ascii
    $s14 = "send = \"open\", oMatchesSelector = \"Script\", guid = \"ADO\", prepend = \"R\";" fullword ascii
    $s15 = "collection = \"tp:\", mozMatchesSelector = \"saveT\";" fullword ascii
    $s16 = "tbody = root[argument + prev + runescape](removeEvent + oMatchesSelector + matcherFromTokens + valHooks + DOMParser);" fullword ascii
    $s17 = "onload[curTop + ajax][mappedTypes](((2293 + result) / (25 & matchExpr)));" fullword ascii
    $s18 = "isTrigger[Sizzle + radio]();" fullword ascii
    $s19 = "attachEvent = promise + radio;" fullword ascii
    $s20 = "isTrigger[mimeType](unit[prepend + grep + nativeStatusText + amd]);" fullword ascii

  condition:
    uint16(0) == 0x6f6d and
    8 of them
}