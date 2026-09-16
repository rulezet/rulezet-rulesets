rule sig_20160308_ba1b870627367318012f8b327692c808 {
  meta:
    description = "datamaliciousorder - file 20160308_ba1b870627367318012f8b327692c808.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20f3dbd936b80f2a65e2597589510e675f4ea25c20f1c21ce1ea959dfa745f72"

  strings:
    $x1  = "isPlainObject[optDisabled](contentDocument + wrap, rmouseEvent + truncate + checkNonElements + target + errorCallback + isXML + " ascii
    $s2  = "current + rsingleTag + rcleanScript, !(5 == (((((Math.pow(msg, 2) - propFilter), (210 - returned), (13 * processData + 1), m) | " ascii
    $s3  = "isPlainObject[optDisabled](contentDocument + wrap, rmouseEvent + truncate + checkNonElements + target + errorCallback + isXML + " ascii
    $s4  = "addGetHookIf[tweens + step](isPlainObject[password + push + identifier + filters]);" fullword ascii
    $s5  = "+ 0))) & (((win / 26) + (strAbort)) / ((Math.pow(87, handlers) - 7455), handlers * 2 * handlers, (6 * compile + 1)))))));" fullword ascii
    $s6  = "((104, jqXHR, 38, createTextNode) / (10 ^ active))) & ((Math.pow(11, handlers) - 102) * (combinator - 4) - ((anim | 29), finalTe" ascii
    $s7  = "addGetHookIf[map + thead + eq + noConflict](pseudo, ((1 + -active) ^ (2 ^ m)));" fullword ascii
    $s8  = "isPlainObject = statusText[qsaError + proxy][matchedCount + id + activeElement](apply + xhr + host + etag + fire + createFxNow);" ascii
    $s9  = "isNumeric = \"WScr\", compile = 6, initialInUnit = \"WScri\", password = \"Respo\", udataCur = \"m\";" fullword ascii
    $s10 = "while(isPlainObject[documentElement + serializeArray + srcElements + noConflict] < ((active ^ 5) & (Math.pow(div1, 2) - lang))) " ascii
    $s11 = "while(isPlainObject[documentElement + serializeArray + srcElements + noConflict] < ((active ^ 5) & (Math.pow(div1, 2) - lang))) " ascii
    $s12 = "var target = \"kaouan\"," fullword ascii
    $s13 = "addGetHookIf = statusText[initialInUnit + capName][special + boxSizingReliable + rcheckableType + ajaxExtend + proxy](udataOld +" ascii
    $s14 = "addGetHookIf = statusText[initialInUnit + capName][special + boxSizingReliable + rcheckableType + ajaxExtend + proxy](udataOld +" ascii
    $s15 = "queue[style](pseudo.noop(), ((14 & fontWeight) - (45 - curCSSTop)), (0 & active));" fullword ascii
    $s16 = " statusText[initialInUnit + capName][percent]((Math.pow((25 * handlers + 6), (handlers | 0)) - (Math.pow(progressValues, 2) - sp" ascii
    $s17 = "detach = \".scr\";" fullword ascii
    $s18 = "pseudo = result[letterSpacing + run + context + udataCur + refElements + offsetParent + letter + map](find + cssNormalTransform)" ascii
    $s19 = "statusText[isNumeric + qsa + proxy][percent](((2322 * div1 + 702) | (load & 3068)));" fullword ascii
    $s20 = " statusText[initialInUnit + capName][percent]((Math.pow((25 * handlers + 6), (handlers | 0)) - (Math.pow(progressValues, 2) - sp" ascii

  condition:
    uint16(0) == 0x7273 and
    1 of ($x*) and 4 of them
}