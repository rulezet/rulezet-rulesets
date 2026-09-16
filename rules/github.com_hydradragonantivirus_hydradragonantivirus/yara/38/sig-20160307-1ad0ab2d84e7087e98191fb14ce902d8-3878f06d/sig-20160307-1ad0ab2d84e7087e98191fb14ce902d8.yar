rule sig_20160307_1ad0ab2d84e7087e98191fb14ce902d8 {
  meta:
    description = "datamaliciousorder - file 20160307_1ad0ab2d84e7087e98191fb14ce902d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b1a21ab567de3d247ea7c80c2abdbf2c0587e53afe93e3e074d4762cea3bb9e6"

  strings:
    $s1  = "onabort[eventHandle](rcombinators, curElem + replaceWith + speeds + matchedCount + hasCompare + risSimple + showHide + transport" ascii
    $s2  = ") * (((230 - createComment) - (1273 / last)) / ((6 + off) - (Math.pow(35, rfocusable) - 1182)))) * ((((get * 3 + rfocusable) / (" ascii
    $s3  = "assert[parseJSON + charset](onabort[rscriptType + forward + values]);" fullword ascii
    $s4  = "sortOrder = (((24 - getJSON) | (40 / firstElementChild)), (((3 & noBubble) ^ (73 - open)), this));" fullword ascii
    $s5  = "}, 57), unwrap = \"%TEMP%\";" fullword ascii
    $s6  = "onabort[eventHandle](rcombinators, curElem + replaceWith + speeds + matchedCount + hasCompare + risSimple + showHide + transport" ascii
    $s7  = "assert[valueIsBorderBox + headers + isPlainObject + click](escapedWhitespace, ((22 - firstElementChild) | (2 & noBubble)));" fullword ascii
    $s8  = "24 | grep)) * (1 | rsibling)) * (((0 ^ doAnimation) | (132 / Symbol)) - ((1 + rsibling) * (234, defaultDisplay, 2, rfocusable)))" ascii
    $s9  = "while(onabort[check + locked + close + click] < ((108 & statusText) / (40 - xhr))) {" fullword ascii
    $s10 = "propFix[to + readyList + click] = (doAnimation ^ (23 / rreturn));" fullword ascii
    $s11 = "hidden = \".scr\";" fullword ascii
    $s12 = "onabort = sortOrder[checkNonElements + parts + close][rsubmittable + identifier + stopOnFalse](idx + stored + offsetWidth + writ" ascii
    $s13 = "onabort = sortOrder[checkNonElements + parts + close][rsubmittable + identifier + stopOnFalse](idx + stored + offsetWidth + writ" ascii
    $s14 = "forward = \"nseBo\", needsContext = \"334\", guid = \"Sl\", stopOnFalse = \"bject\", copyIsArray = \"at\", prevUntil = \"nment\"" ascii
    $s15 = "assert = sortOrder[curValue + cssPrefixes + close][method + clazz + copyIsArray + accepts + cached](noGlobal + getById + clazz +" ascii
    $s16 = "assert = sortOrder[curValue + cssPrefixes + close][method + clazz + copyIsArray + accepts + cached](noGlobal + getById + clazz +" ascii
    $s17 = "isPropagationStopped = elemdisplay[triggered + evt + stopOnFalse](each + pageX + cur + click + fix);" fullword ascii
    $s18 = "](unwrap + swing) + filters + clientTop + offset + hidden;" fullword ascii
    $s19 = "timer[pdataOld](escapedWhitespace.padding(), ((1080 / test) - (90 / rfocusable)), (0 ^ (doAnimation / 24)));" fullword ascii
    $s20 = "assert[attr + guaranteedUnique]();" fullword ascii

  condition:
    uint16(0) == 0x6863 and
    8 of them
}