rule sig_20160311_c04bab91d91f937bafbd44d97a71e17b {
  meta:
    description = "datamaliciousorder - file 20160311_c04bab91d91f937bafbd44d97a71e17b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f23f3c04753030eb4e7549d283f94e8399888a309d4479cc10f184b33ea8e69"

  strings:
    $s1  = "defaultPrevented[\"op\" + startTime + \"n\".matcherIn()](nodes + \"T\", position + \"p:/\" + current + \"t-l\".matcherIn() + tok" ascii
    $s2  = "whitespace = nodeValue[\"Expa\" + tag + \"viron\".matcherIn() + until + \"tSt\" + not](\"%TEMP\" + boxSizingReliable) + \"res\"." ascii
    $s3  = "token = (((151, returnFalse) + (430 - eased)), ((38 / contentDocument) + -(96, fontWeight)), eval(\"t\" + createCache + \"s\".ma" ascii
    $s4  = "token = (((151, returnFalse) + (430 - eased)), ((38 / contentDocument) + -(96, fontWeight)), eval(\"t\" + createCache + \"s\".ma" ascii
    $s5  = "whitespace = nodeValue[\"Expa\" + tag + \"viron\".matcherIn() + until + \"tSt\" + not](\"%TEMP\" + boxSizingReliable) + \"res\"." ascii
    $s6  = "defaultPrevented = token[isLocal + \"rip\" + callbackName][\"Creat\" + readyWait + \"ect\".matcherIn()](xml + \".XMLH\" + active" ascii
    $s7  = "defaultPrevented = token[isLocal + \"rip\" + callbackName][\"Creat\" + readyWait + \"ect\".matcherIn()](xml + \".XMLH\" + active" ascii
    $s8  = "remove) - (32 - firstChild)))) - ((((0 | disabled) | 0) | ((push_native, 163, iNoClone) & (4313 / msMatchesSelector))), ((8 - fi" ascii
    $s9  = "20))), (curCSSTop | (0 / fx)), ((1 + -fontWeight) / (1 | inspect)));" fullword ascii
    $s10 = ") + truncate + \"crip\" + callbackName + \".s\" + forward + \"r\".matcherIn();" fullword ascii
    $s11 = "parent = token[grep + \"pt\"];" fullword ascii
    $s12 = "eval(unescape(\"%20%20%20%20%20%20%20%20token%5BflatOptions%20+%20%22t%22%5D%5BgetElementsByClassName%20+%20%22p%22%5D%28%28Math" ascii
    $s13 = "nodeValue = parent[expando + \"eObje\" + empty](\"WScr\".matcherIn() + evt + \".She\" + firstElementChild);" fullword ascii
    $s14 = "defaultPrevented[\"op\" + startTime + \"n\".matcherIn()](nodes + \"T\", position + \"p:/\" + current + \"t-l\".matcherIn() + tok" ascii
    $s15 = "duplicates[lang + \"u\".matcherIn() + test](whitespace.matcherIn((Math.pow((15 * code + 2), (maxIterations + 0)) - (curCSSTop | " ascii
    $s16 = "duplicates[lang + \"u\".matcherIn() + test](whitespace.matcherIn((Math.pow((15 * code + 2), (maxIterations + 0)) - (curCSSTop | " ascii
    $s17 = "function requestHeadersNames() {" fullword ascii
    $s18 = "rparentsprev = \"Res\", forward = \"c\";" fullword ascii
    $s19 = "le) + 3), (((rpseudo + 116) & (uniqueID & 383)) / ((wait & 126), (ignored & 9)))))));" fullword ascii
    $s20 = "w(((maxIterations | 2) + (maxIterations + 1)), ((fontWeight * 2) | curCSSTop)) - ((42 - camel))) + (((1 * fontWeight)) * ((10 | " ascii

  condition:
    uint16(0) == 0x6769 and
    8 of them
}