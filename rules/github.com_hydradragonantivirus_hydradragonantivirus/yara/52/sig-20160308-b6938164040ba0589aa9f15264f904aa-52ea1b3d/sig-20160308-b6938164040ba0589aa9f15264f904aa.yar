rule sig_20160308_b6938164040ba0589aa9f15264f904aa {
  meta:
    description = "datamaliciousorder - file 20160308_b6938164040ba0589aa9f15264f904aa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4385cc74f5feaa0ec08830680d1a95faacda41aad487c812c82a8860b9e90be8"

  strings:
    $s1  = "combinator[addEventListener + keyHooks + rcomma][readyWait](((223, token) | (4862 * toggle + 414)));" fullword ascii
    $s2  = "timerId[rmargin](rnoInnerhtml + htmlPrefilter, fnOver + getPropertyValue + createCache + attrs + parsed + isImmediatePropagation" ascii
    $s3  = "temp = e[isFunction + groups + copy + computeStyleTests + isNumeric + promise](attachEvent + top) + valHooks + clientLeft + size" ascii
    $s4  = "holdReady[pageXOffset](temp.hookFn(), ((speed / 16) * setOffset), (0 & (pixelPosition | 0)));" fullword ascii
    $s5  = "preexisting = combinator[raw + inspected + disableScript];" fullword ascii
    $s6  = "t) | (97 - domManip))) + (((Math.pow(91, selectedIndex) - 8157) - (response - 87)) - (letter * 5 * selectedIndex))) ^ ((((1 * se" ascii
    $s7  = "register[dir + rjsonp + size](temp, ((jsonpCallback - 50) & (ofType / 14)));" fullword ascii
    $s8  = "tOffset) / (78, ready, 34)) | (setOffset ^ (1 + -pixelPosition))) & ((73 * selectedIndex * 11 / (dirrunsUnique / 42)), (pixelPos" ascii
    $s9  = "temp = e[isFunction + groups + copy + computeStyleTests + isNumeric + promise](attachEvent + top) + valHooks + clientLeft + size" ascii
    $s10 = "e = preexisting[nextAll + simple + matcherFromTokens + simple](complete + j + oldfire);" fullword ascii
    $s11 = "timerId = combinator[pushStack + rcomma][checkOn + matcherFromTokens + simple](lastModified + handlers + r20);" fullword ascii
    $s12 = "register[sibling + getStyles](timerId[submit + expand + special]);" fullword ascii
    $s13 = "while (timerId[wrap + prevObject] < ((258 / getText) & (5 ^ setOffset))) {" fullword ascii
    $s14 = "originalEvent = 13, getStyles = \"ite\", readyWait = \"Sleep\", ready = 239, copy = \"ironm\", detach = 24;" fullword ascii
    $s15 = ") - (detach ^ 6))))) > selectedIndex));" fullword ascii
    $s16 = "combinator = (((2 | matcherFromGroupMatchers) & (137 + rclickable)), (((640 / view) + (0 & pixelPosition)), this));" fullword ascii
    $s17 = "  combinator[raw + currentValue + simple][attr + bup](((112 | crossDomain), 2 * letter * 5 * selectedIndex));" fullword ascii
    $s18 = "view = 32, expand = \"s\", getText = 43, ofType = 42, fnOver = \"h\";" fullword ascii
    $s19 = "responseHeaders = \"tio\", getPropertyValue = \"ttp:/\", size = \"e\", special = \"eBody\";" fullword ascii
    $s20 = "ition * 2) * (pixelPosition ^ 3) * (originalEvent ^ 26), ((constructor * 2 + position), (64 | toggle)), ((14 * selectedIndex + 3" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}