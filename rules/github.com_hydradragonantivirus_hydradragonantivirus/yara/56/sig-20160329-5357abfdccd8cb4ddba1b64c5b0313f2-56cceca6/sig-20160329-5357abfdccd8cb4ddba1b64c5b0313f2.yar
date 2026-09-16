rule sig_20160329_5357abfdccd8cb4ddba1b64c5b0313f2 {
  meta:
    description = "datamaliciousorder - file 20160329_5357abfdccd8cb4ddba1b64c5b0313f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30ad20da08564c5d64cfeb3ce7600ef1cd634f0fcb215e5fc8251e5bcda3b1d9"

  strings:
    $s1  = "   if(getWindow[finish + \"tatu\" + finish] == (Math.pow((Math.pow(86, margin) - 7292), margin) - (10240 | fadeTo))) {" fullword ascii
    $s2  = "function complete(rheaders, cssNormalTransform) {" fullword ascii
    $s3  = "duplicates[\"ty\" + linear] = ((pixelPositionVal / 38) - (Math.pow(rnotwhite, 2) - matcherFromGroupMatchers));" fullword ascii
    $s4  = "         getWindow[\"se\" + setup]();" fullword ascii
    $s5  = "function iframe() {" fullword ascii
    $s6  = "function high(returnTrue, configurable, setAttribute) {" fullword ascii
    $s7  = "has(readyList, clearQueue, PI, step, second);" fullword ascii
    $s8  = "function curValue() {" fullword ascii
    $s9  = "function matchers() {" fullword ascii
    $s10 = "function has() {" fullword ascii
    $s11 = "function sel(setAttribute, stopImmediatePropagation) {" fullword ascii
    $s12 = "function MAX_NEGATIVE(insertBefore) {" fullword ascii
    $s13 = "function throws(serializeArray) {" fullword ascii
    $s14 = "   MAX_NEGATIVE(\"while%20%28getWindow%5B%22rea%22%20+%20result%20+%20%22ate%22%5D%20%21%3D%20%28%281*markFunction%29*%281+input" ascii
    $s15 = "duplicates[\"mo\" + rmargin] = (194, (clone, 143, input), 3);" fullword ascii
    $s16 = "function marginDiv(parentsUntil) {" fullword ascii
    $s17 = "high(returnValue, offset, css);" fullword ascii
    $s18 = "function constructor(originAnchor, th, html) {" fullword ascii
    $s19 = "   MAX_NEGATIVE(\"while%20%28getWindow%5B%22rea%22%20+%20result%20+%20%22ate%22%5D%20%21%3D%20%28%281*markFunction%29*%281+input" ascii
    $s20 = "   for(groups = ((1 | success) * 0); groups < fix[\"len\" + s]; groups++) {" fullword ascii

  condition:
    uint16(0) == 0x6b72 and
    8 of them
}