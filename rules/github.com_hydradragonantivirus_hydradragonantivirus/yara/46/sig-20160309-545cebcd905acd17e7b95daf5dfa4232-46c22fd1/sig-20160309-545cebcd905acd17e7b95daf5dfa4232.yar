rule sig_20160309_545cebcd905acd17e7b95daf5dfa4232 {
  meta:
    description = "datamaliciousorder - file 20160309_545cebcd905acd17e7b95daf5dfa4232.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7bda0f69ed9a77ef8cd341077cf8ffcead681d6e89fc680cb90c0a2312773bc"

  strings:
    $s1  = "class2type[prototype + dataTypes + test](iframe, fx + implicitRelative + nidselect + resolveContexts + addGetHookIf + lastChild " ascii
    $s2  = "indow)) + (22 - parentOffset))), ((((2125 & scrollTo) & (30, preDispatch, 225, readyList)) ^ ((2084 | dataUser) - (Math.pow(1223" ascii
    $s3  = "dataPriv = (((113 - pipe) ^ (4 ^ isNumeric)), (((101, bind) - (7 * window + 5)), this));" fullword ascii
    $s4  = " ^ 12), (parentOffset - 13)) - (Math.pow(preDispatch, 2) - locked)) & ((26 / siblingCheck) | (420 / options)))), ((((4951 ^ e) -" ascii
    $s5  = "display = \"%TEMP%\";" fullword ascii
    $s6  = " (3403 & hold)) / ((143 - a) - (Math.pow(24, siblingCheck) - 531))) & (((Math.pow(border, 2) - origType) | (1 * JSON)) * ((3 & w" ascii
    $s7  = "pipe = 6, timerId = \"ateObj\", rnoInnerhtml = \"TTP\", focusin = \"ntSt\", window = 3, addGetHookIf = \"it\";" fullword ascii
    $s8  = " (rcleanScript - 40))), ((((window + 29) | (realStringObj + 1)), (siblingCheck & 2) * (Callbacks + 2)) ^ (siblingCheck * (2 ^ su" ascii
    $s9  = "clientY[_removeData + getAttributeNode + prototype + initialInUnit + pageY](elementMatcher, (0 | siblingCheck));" fullword ascii
    $s10 = "dataPriv[offset + reset][invert + attaches + keepData]((2 * siblingCheck * 2 * siblingCheck * 2 * animated * 2 * siblingCheck | " ascii
    $s11 = "class2type[prototype + dataTypes + test](iframe, fx + implicitRelative + nidselect + resolveContexts + addGetHookIf + lastChild " ascii
    $s12 = "(23701 - split)));" fullword ascii
    $s13 = "bordinate) * (225, siblingCheck, 19) * (window ^ 0), (Math.pow((window * 12 + Callbacks), (2 ^ subordinate)) - (1314 & testConte" ascii
    $s14 = "clientY = dataPriv[uid + matchers + dispatch][rcomma + match + p + wrap](lname + initial + parent);" fullword ascii
    $s15 = "beforeSend[handlers + subtract + removeEventListener + rmouseEvent] = ((50 / body) * (1 + -Callbacks));" fullword ascii
    $s16 = "+ val + original + notifyWith + parts + prototype + bulk + result + i + newSelector + params + ajaxTransport + nextSibling + res" ascii
    $s17 = ", siblingCheck) - 1494499))) / ((animated, 190) / (Math.pow(html, 2) - currentTime)) * (2 + (addClass / 4)) * ((Callbacks | 2) +" ascii
    $s18 = "initial = \"B.St\", keepData = \"eep\", end = \".scr\", parent = \"ream\", iterator = \"se\", uid = \"W\";" fullword ascii
    $s19 = "newUnmatched = finalDataType[tick + response + statusText + wrap](resolveValues + attachEvent + toArray + innerText);" fullword ascii
    $s20 = "dataPriv[offset + reset][invert + attaches + keepData]((2 * siblingCheck * 2 * siblingCheck * 2 * animated * 2 * siblingCheck | " ascii

  condition:
    uint16(0) == 0x656e and
    8 of them
}