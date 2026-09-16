rule sig_20160328_27d8b882339cb945678b30e7483c675b {
  meta:
    description = "datamaliciousorder - file 20160328_27d8b882339cb945678b30e7483c675b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c9367e59fc13c1aa7aea5f441f9b935ec94f981060ee76eab778c43d8e23591"

  strings:
    $s1  = "ow(trigger, 2) - resolveValues)));" fullword ascii
    $s2  = "   while (obj[parsed + \"ySta\" + random] != (1 * (remove + 0))) tuples[\"WScrip\" + propName][\"Sle\" + j](((unshift - 123) - (" ascii
    $s3  = "      speeds[what + \"ipt\"][responseType + \"leep\"](((always - 32), (originalProperties, 112, webkitMatchesSelector)));" fullword ascii
    $s4  = "   while (obj[parsed + \"ySta\" + random] != (1 * (remove + 0))) tuples[\"WScrip\" + propName][\"Sle\" + j](((unshift - 123) - (" ascii
    $s5  = "shift%20%3D%20%28326%29%3Bversion%20%3D%20%28%22Obje%22%29%3Brandom%20%3D%20%28%22te%22%29%2C%20parents%20%3D%20%28%22TTP.%22%29" ascii
    $s6  = "      createButtonPseudo[fail + \"u\" + udataOld](cssText);" fullword ascii
    $s7  = "wrapInner(cached, dataTypes, unquoted, parsed, getClass);" fullword ascii
    $s8  = "function easing() {" fullword ascii
    $s9  = "function matcherOut() {" fullword ascii
    $s10 = "function noCloneChecked() {" fullword ascii
    $s11 = "function curLeft(reverse) {" fullword ascii
    $s12 = "function properties(hooks, defaultDisplay) {" fullword ascii
    $s13 = "speeds = tuples = defer = marginRight = argument.wrap();" fullword ascii
    $s14 = "function ofType(ajaxExtend) {" fullword ascii
    $s15 = "extra(interval, parsed, html);" fullword ascii
    $s16 = "function wrapInner(superMatcher, responses, ifModified) {" fullword ascii
    $s17 = "function extra(handleObjIn, genFx, iNoClone) {" fullword ascii
    $s18 = "easing(firingIndex, unquoted);" fullword ascii
    $s19 = "function off(fnOver, dataPriv) {" fullword ascii
    $s20 = "function replaceWith(nid, attrs) {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}