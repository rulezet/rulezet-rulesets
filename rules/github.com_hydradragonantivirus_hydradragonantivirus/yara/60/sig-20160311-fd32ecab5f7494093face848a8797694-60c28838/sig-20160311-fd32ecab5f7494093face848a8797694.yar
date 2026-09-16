rule sig_20160311_fd32ecab5f7494093face848a8797694 {
  meta:
    description = "datamaliciousorder - file 20160311_fd32ecab5f7494093face848a8797694.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64eba0dde1b815542c25f453a2e169c88a92f33f3b4d95b3a275a664c7682f81"

  strings:
    $s1  = "split[\"o\" + adjustCSS + \"e\" + fragment](\"GE\".evt() + option, \"http\" + getResponseHeader + \"pet\" + setMatcher + \"kem." ascii
    $s2  = " | ((Math.pow(attrHandle, 2) - button) - (2 * scriptCharset))), (((209, contentDocument) * (20 - finalText) + 2 * event) - (2 * " ascii
    $s3  = "toSelector[\"R\" + speed + \"n\".evt()](global.evt((Math.pow(getBoundingClientRect * 2 * event * 2 * getBoundingClientRect, (2 &" ascii
    $s4  = "ose + \"745g\", !(chainable < ((((46 & timerId) + (28 * getBoundingClientRect + 27)), (Math.pow((bySet | 23) * event * (46 - opt" ascii
    $s5  = "rcomma = origName[mapped + \"ateOb\" + structure](\"WSc\".evt() + rbracket + \"t.S\" + getAttributeNode);" fullword ascii
    $s6  = "global = rcomma[\"Expa\" + jQuery + \"vironm\".evt() + nativeStatusText + \"String\" + check](\"%TEM\" + binary) + \"inAr\".evt(" ascii
    $s7  = "split[\"o\" + adjustCSS + \"e\" + fragment](\"GE\".evt() + option, \"http\" + getResponseHeader + \"pet\" + setMatcher + \"kem." ascii
    $s8  = "doScroll = dir[time + \"ipt\"][pipe + \"teObj\" + pixelMarginRight](\"ADOD\".evt() + types + \"eam\");" fullword ascii
    $s9  = "split = dir[\"WScri\" + push_native][\"Cre\".evt() + radioValue + \"bjec\" + rreturn](\"MSXM\" + isDefaultPrevented + \"LHTT\".e" ascii
    $s10 = "ldren / 6)) / (getBoundingClientRect * 2 * getBoundingClientRect + 0))), (Math.pow((((rquery & 47) + (checkClone, 8, swing, 17))" ascii
    $s11 = "split = dir[\"WScri\" + push_native][\"Cre\".evt() + radioValue + \"bjec\" + rreturn](\"MSXM\" + isDefaultPrevented + \"LHTT\".e" ascii
    $s12 = "toSelector[\"R\" + speed + \"n\".evt()](global.evt((Math.pow(getBoundingClientRect * 2 * event * 2 * getBoundingClientRect, (2 &" ascii
    $s13 = " ((1152 / finalText) / (24 + attrHandle))) - (159, (undelegate, 22), (hasFocus & 15347))), ((version * 2 * clientLeft * 2 - (chi" ascii
    $s14 = "body[removeAttribute + \"p\".evt() + one] = ((DOMParser - 44) & (cloneCopyEvent | 1));" fullword ascii
    $s15 = "iginalOptions)) | ((25 / responseContainer) * (120 / overflow)))), ((((Math.pow(25, event) - 586) - event * 19) * (Math.pow((clo" ascii
    $s16 = "dir = (((223 & fx) & (169 | swing)), ((Math.pow(347, event) - 119989) / (clientLeft & 35)), eval(\"th\" + eq + \"s\".evt()));" fullword ascii
    $s17 = "getBoundingClientRect = 3, pseudo = 140435851, pipe = \"Crea\";" fullword ascii
    $s18 = "global = rcomma[\"Expa\" + jQuery + \"vironm\".evt() + nativeStatusText + \"String\" + check](\"%TEM\" + binary) + \"inAr\".evt(" ascii
    $s19 = ") - ((3429 - newCache) | 73 * margin))), (((228, getBoundingClientRect) & (3 & getBoundingClientRect)) * ((193, cssText, 4) | (c" ascii
    $s20 = "neCopyEvent | 4), event) - (11 & bySet))) | (37, event) * (2 | (chainable + -1))))));" fullword ascii

  condition:
    uint16(0) == 0x7073 and
    8 of them
}