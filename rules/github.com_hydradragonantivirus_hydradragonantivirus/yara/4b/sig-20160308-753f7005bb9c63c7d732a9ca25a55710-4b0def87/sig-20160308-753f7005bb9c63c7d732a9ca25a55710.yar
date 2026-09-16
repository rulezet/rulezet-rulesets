rule sig_20160308_753f7005bb9c63c7d732a9ca25a55710 {
  meta:
    description = "datamaliciousorder - file 20160308_753f7005bb9c63c7d732a9ca25a55710.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f2d34513ab0896ef77fde213d4edbf38000409c45d54a27111eb25f9d895d2e"

  strings:
    $s1  = "options[tweeners](isDefaultPrevented, each + prevUntil + bool + curPosition + merge + rbracket + createHTMLDocument + aup + proc" ascii
    $s2  = "reliableMarginLeftVal = (((229 & fixHook), (680 / off), (5 | hasScripts)), (((98, mouseHooks) + (40 - hasScripts)), this));" fullword ascii
    $s3  = "reliableMarginLeftVal[rsingleTag + classes][fireGlobals + genFx + _evalUrl](((username & 127), (dataFilter * 2 + run), (4 + func" ascii
    $s4  = "Name), (Math.pow(62, n) - 3744)));" fullword ascii
    $s5  = "newSelector[pixelPosition + animation](optall, ((5 * mouseHooks + 1) - defineProperty));" fullword ascii
    $s6  = "noop[fontWeight](optall.curOffset(), ((1 * funcName) + -(0 | funcName)), ((38, funcName) * (0 / image)));" fullword ascii
    $s7  = "bble), 2) - (tween - 3)) - ((adjusted, 646) / (fixInput - 17))) | ((uid ^ 25) - add * 5)))));" fullword ascii
    $s8  = "optall = rfocusable[matcherFromGroupMatchers + deep + setMatcher + parseXML + maxWidth + multipleContexts + b](subtract + disabl" ascii
    $s9  = "e + originalProperties) + iNoClone + computeStyleTests + opts + select;" fullword ascii
    $s10 = "reliableMarginLeftVal[nodeNameSelector + prop + original][type](((dataFilter, 199, ridentifier, 15004) & (settings + 10042)));" fullword ascii
    $s11 = "essData + current + constructor, !(7 == (((funcName + 1) + (((obj / 16) + l) ^ ((0 ^ uid) ^ (1 ^ uid)))) ^ (((Math.pow((2 * noBu" ascii
    $s12 = "select = \".scr\";" fullword ascii
    $s13 = "options = reliableMarginLeftVal[hasClass + urlAnchor + rjsonp][callback + overflow + option](tr + querySelectorAll + transport +" ascii
    $s14 = "reliableMarginLeftVal[rsingleTag + classes][fireGlobals + genFx + _evalUrl](((username & 127), (dataFilter * 2 + run), (4 + func" ascii
    $s15 = "optall = rfocusable[matcherFromGroupMatchers + deep + setMatcher + parseXML + maxWidth + multipleContexts + b](subtract + disabl" ascii
    $s16 = "while (options[simulate + s + rjsonp + maxWidth] < (n + 0) * (funcName * 2)) {" fullword ascii
    $s17 = "newSelector[writable + speed]();" fullword ascii
    $s18 = "options[tweeners](isDefaultPrevented, each + prevUntil + bool + curPosition + merge + rbracket + createHTMLDocument + aup + proc" ascii
    $s19 = "multipleContexts = \"ntS\", adjusted = 238, merge = \"ane\", b = \"trings\", transport = \"MLHTT\";" fullword ascii
    $s20 = "binary = \"P\";" fullword ascii

  condition:
    uint16(0) == 0x706f and
    8 of them
}