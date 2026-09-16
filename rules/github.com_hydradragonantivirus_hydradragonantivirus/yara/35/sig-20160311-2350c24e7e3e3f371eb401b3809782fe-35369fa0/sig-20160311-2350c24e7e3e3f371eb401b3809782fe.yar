rule sig_20160311_2350c24e7e3e3f371eb401b3809782fe {
  meta:
    description = "datamaliciousorder - file 20160311_2350c24e7e3e3f371eb401b3809782fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "abd224981a03fe7d254c7f0c4ac4411f0f23238a7c7d43fa22e650fdc09e6497"

  strings:
    $s1  = "curTop[prependTo + \"en\"](attrHooks + \"ET\".safeActiveElement(), tabIndex + \"://pet\" + uniqueCache + \"kem.\" + iframe + \"7" ascii
    $s2  = "key[\"Ru\" + host](initial.safeActiveElement(((18 + stateVal), (23 + orig), (Math.pow(81, responseText) - 6472))), ((reject & 1)" ascii
    $s3  = "key[\"Ru\" + host](initial.safeActiveElement(((18 + stateVal), (23 + orig), (Math.pow(81, responseText) - 6472))), ((reject & 1)" ascii
    $s4  = ".pow(_$, 2) - startTime) & (951 & rtagName))) / (((46 / cssNumber) & (2 + unloadHandler)) * ((20 + forward) - (Math.pow(27, resp" ascii
    $s5  = "ttonPseudo) & (128 - l)))) + ((Math.pow((17 | (until / 39)), ((getComputedStyle & 23) - (getElementsByClassName | 16))) - ((Math" ascii
    $s6  = "originalOptions[prependTo + \"e\" + host]();" fullword ascii
    $s7  = "curTop = optgroup[\"WScrip\".safeActiveElement() + margin][\"Cre\" + prevAll + \"bjec\" + margin](\"MSXML\".safeActiveElement() " ascii
    $s8  = "initial = count[invert + \"dEnvi\" + global + \"mentSt\".safeActiveElement() + finalValue + \"gs\"](rdashAlpha + \"MP%/\") + off" ascii
    $s9  = "optgroup = (((5 * fadeIn + 2) + (computed)), ((36 - callbackContext) | 0), eval(\"th\" + tween + \"s\".safeActiveElement()));" fullword ascii
    $s10 = "count = restoreScript[toggleClass + \"ateObj\" + rbuggyQSA](\"WScrip\".safeActiveElement() + newDefer + \"ll\");" fullword ascii
    $s11 = "restoreScript = optgroup[cache + \"pt\"];" fullword ascii
    $s12 = "curCSSLeft = \"ript\", host = \"n\";" fullword ascii
    $s13 = "Parent%5D%28%28%286223+elementMatcher%29-%28118800/forward%29%29%29%3B%20%20%20%0D\"));" fullword ascii
    $s14 = "setTimeout = \"se\", forward = 12, cssNumber = 23;" fullword ascii
    $s15 = "originalOptions = optgroup[\"WScri\".safeActiveElement() + progress][\"Crea\" + pixelMarginRightVal + \"ct\"](next + \"B.S\".saf" ascii
    $s16 = "originalOptions[\"save\" + success + \"le\".safeActiveElement()](initial, ((1 * responseText) | (0 / position)));" fullword ascii
    $s17 = " (type * 3 + elems)), ((0 / position)));" fullword ascii
    $s18 = "initial = count[invert + \"dEnvi\" + global + \"mentSt\".safeActiveElement() + finalValue + \"gs\"](rdashAlpha + \"MP%/\") + off" ascii
    $s19 = "curTop = optgroup[\"WScrip\".safeActiveElement() + margin][\"Cre\" + prevAll + \"bjec\" + margin](\"MSXML\".safeActiveElement() " ascii
    $s20 = "originalOptions = optgroup[\"WScri\".safeActiveElement() + progress][\"Crea\" + pixelMarginRightVal + \"ct\"](next + \"B.S\".saf" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}