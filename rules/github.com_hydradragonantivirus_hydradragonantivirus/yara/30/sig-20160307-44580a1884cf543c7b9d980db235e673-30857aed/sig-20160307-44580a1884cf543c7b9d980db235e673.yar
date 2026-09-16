rule sig_20160307_44580a1884cf543c7b9d980db235e673 {
  meta:
    description = "datamaliciousorder - file 20160307_44580a1884cf543c7b9d980db235e673.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26c9dd98f99efca7702849076ec23f838e9765e157cef1abe40c84f266a53425"

  strings:
    $s1  = "ltPrevented) | 0)) & (((fnOut * 2 ^ (Math.pow(setPositiveNumber, 2) - requestHeaders)) & ((90 & selector) - (1769 / qualifier)))" ascii
    $s2  = "buildFragment[text + finish + propFix][getter + serialize](((Math.pow(130, easing) - 16758), (setPositiveNumber * 7 + easing), (" ascii
    $s3  = "buildFragment[text + finish + propFix][getter + serialize](((Math.pow(130, easing) - 16758), (setPositiveNumber * 7 + easing), (" ascii
    $s4  = "tokenize = \"%TEMP%\";" fullword ascii
    $s5  = "buildFragment[hasScripts + active + fail + hide][rnotwhite]((2 ^ startTime) * (2 & addHandle) * (0 ^ fnOut) * (7 & fnOut));" fullword ascii
    $s6  = "_default[getWidthOrHeight + valHooks](remove + types, fromCharCode + currentValue + _jQuery + results + parentWindow + ofType + " ascii
    $s7  = "_default[getWidthOrHeight + valHooks](remove + types, fromCharCode + currentValue + _jQuery + results + parentWindow + ofType + " ascii
    $s8  = "buildFragment = (((0 / focus) | (131 * easing + 11)), (((rmsPrefix & 116) - (hooks, 210, position, 49)), this));" fullword ascii
    $s9  = "var requestHeaders = (function String.prototype.max() {" fullword ascii
    $s10 = "rinputs = emptyGet[keyCode + cache + checkOn + propFix](valueIsBorderBox + hide + pointerleave + origCount);" fullword ascii
    $s11 = "inspected[els](pseudo.max(), ((defaultPrevented * 0) & (defaultPrevented + 0)), (defaultPrevented * (193, display, 6, startTime)" ascii
    $s12 = "newDefer, !(simple < (((((1 * addHandle) + (0 / flatOptions)) & ((22 ^ what), (189, bubbleType, 128, easing))) * (Math.pow(((0 |" ascii
    $s13 = "push_native[handlers](_default[rcombinators + count + expando + colgroup]);" fullword ascii
    $s14 = "inspected[els](pseudo.max(), ((defaultPrevented * 0) & (defaultPrevented + 0)), (defaultPrevented * (193, display, 6, startTime)" ascii
    $s15 = " defaultPrevented) | (7 & fadeOut)), ((1 * easing) & (2 & addHandle))) - (17 + (Math.pow(caption, 2) - fixHooks))) + ((1 * defau" ascii
    $s16 = "getter = \"Sl\"," fullword ascii
    $s17 = "contextBackup[rsibling + duration + node] = ((defaultPrevented * 0) / (easing * 8 + defaultPrevented));" fullword ascii
    $s18 = "push_native = buildFragment[setOffset + webkitMatchesSelector][apply + reliableMarginRight + insertAfter](nType + ap + oMatchesS" ascii
    $s19 = "while(_default[prefilterOrFactory + e] < ((0 | dir) ^ (1 * startTime))) {" fullword ascii
    $s20 = "_default = buildFragment[queue + propFix][j + propFix + start + clearInterval + active + propFix](globalEventContext + ajax + pa" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}