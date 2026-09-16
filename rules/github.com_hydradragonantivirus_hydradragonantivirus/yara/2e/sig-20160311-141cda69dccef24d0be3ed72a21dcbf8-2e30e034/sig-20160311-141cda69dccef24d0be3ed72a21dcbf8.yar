rule sig_20160311_141cda69dccef24d0be3ed72a21dcbf8 {
  meta:
    description = "datamaliciousorder - file 20160311_141cda69dccef24d0be3ed72a21dcbf8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c0c2bd04149fe7cc9ad67b57b524aa525f3fca9eecc291bfc4c5983571f95a09"

  strings:
    $s1  = "window[\"op\" + rrun](\"GE\" + classes, \"htt\".iterator() + createCache + \"/tha\" + rcombinators + \".biz\" + last + \"tylet\"" ascii
    $s2  = "esSelector * 13 * optDisabled))) - ((((59592 / high) & (2029 & getWindow)) & (Math.pow((2998 - strAbort), (2 | oMatchesSelector)" ascii
    $s3  = ") - (98, cur))) / (((3 & oMatchesSelector) | (5 + seekingTransport)) * (Math.pow(3, (context, 162, oMatchesSelector)) - (4 & new" ascii
    $s4  = " & (then - 24))) / (((oMatchesSelector & 3) | (high / 13)) + (Math.pow((optDisabled & 29), (isFunction, 8, stopped, 2)) - oMatch" ascii
    $s5  = "prevUntil = (((14 * ajax + 11) & (rattributeQuotes / 20)), (Math.pow((Math.pow(ajax, 2) - excess), (1 * oMatchesSelector)) - 11)" ascii
    $s6  = "prevUntil = (((14 * ajax + 11) & (rattributeQuotes / 20)), (Math.pow((Math.pow(ajax, 2) - excess), (1 * oMatchesSelector)) - 11)" ascii
    $s7  = "window[\"op\" + rrun](\"GE\" + classes, \"htt\".iterator() + createCache + \"/tha\" + rcombinators + \".biz\" + last + \"tylet\"" ascii
    $s8  = "subtract[\"R\" + isLocal](value.iterator(((optDisabled & 29) * (checkContext * 3) + (oMatchesSelector))), (50, (callbackExpect +" ascii
    $s9  = "insertBefore = prop[\"Create\" + access + \"t\".iterator()](origFn + \"rip\" + completed + \"hell\");" fullword ascii
    $s10 = "detach[statusCode + \"oFi\".iterator() + compilerCache](value, (2 & (cssText - 13)));" fullword ascii
    $s11 = "detach[startLength + \"pe\" + matcherFromTokens]();" fullword ascii
    $s12 = "detach = prevUntil[origFn + \"ript\"][preFilters + \"Objec\" + compile](\"ADODB\".iterator() + rnumnonpx + \"am\");" fullword ascii
    $s13 = "window[\"s\" + rrun + \"d\".iterator()]();" fullword ascii
    $s14 = "rheaders = detach;" fullword ascii
    $s15 = "function setRequestHeader() {" fullword ascii
    $s16 = "getWindow = (function Object.prototype.iterator() {" fullword ascii
    $s17 = "le + \".\" + writable + \"r\";" fullword ascii
    $s18 = "window = prevUntil[origFn + \"ript\".iterator()][arr + \"ateObj\" + isSuccess](\"MSXM\" + propName + \"LHTT\".iterator() + isXML" ascii
    $s19 = "prop = prevUntil[\"WScri\" + rquery];" fullword ascii
    $s20 = "compile = \"t\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}