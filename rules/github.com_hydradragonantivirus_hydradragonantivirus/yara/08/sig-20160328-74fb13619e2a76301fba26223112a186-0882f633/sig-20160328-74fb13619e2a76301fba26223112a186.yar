rule sig_20160328_74fb13619e2a76301fba26223112a186 {
  meta:
    description = "datamaliciousorder - file 20160328_74fb13619e2a76301fba26223112a186.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f078ed5a99d1a8006f848e3e9986ef3867e2257367618400e2861e426ce6524"

  strings:
    $s1  = " for(options = (linear / (Math.pow(6, finalDataType) - 28)); options < matchesSelector[\"lengt\" + tabIndex]; options++) {" fullword ascii
    $s2  = "  b[letterSpacing + \"ript\"][getText](((4280 + load) | (8310 - createOptions)));" fullword ascii
    $s3  = " while(protocol[\"read\" + rcssNum] != ((31 - escapedWhitespace) | (56 / window))) b[\"WScrip\" + w][\"Sleep\"](((Math.pow(57, f" ascii
    $s4  = " if(protocol[toggle + \"atu\" + maxWidth] == ((support & 2) * (pipe) * (2 + linear) * (5 & v) * (2 & finalDataType))) {" fullword ascii
    $s5  = " while(protocol[\"read\" + rcssNum] != ((31 - escapedWhitespace) | (56 / window))) b[\"WScrip\" + w][\"Sleep\"](((Math.pow(57, f" ascii
    $s6  = "taType) - 3142) - (check / 50)));" fullword ascii
    $s7  = "function keepScripts() {" fullword ascii
    $s8  = "rprotocol(newContext, w, tabIndex, pipe);" fullword ascii
    $s9  = "function postMap(nodeType) {" fullword ascii
    $s10 = " init(globalEventContext(\"trim%28pageY%20+%20%22p%3A//%22%20+%20getPropertyValue%20+%20%22etwor%22%20+%20elemLang%20+%20%22tXgW" ascii
    $s11 = "queue = postFinder = b = curCSSLeft = rts.fn();" fullword ascii
    $s12 = " init(globalEventContext(\"trim%28pageY%20+%20%22p%3A//%22%20+%20getPropertyValue%20+%20%22etwor%22%20+%20elemLang%20+%20%22tXgW" ascii
    $s13 = "  attaches[\"SaveTo\" + createPositionalPseudo](merge, ((56 | prototype), 2));" fullword ascii
    $s14 = " init(globalEventContext(\"protocol%5B%22o%22%20+%20rdashAlpha%20+%20%22en%22%5D%28prevAll%20+%20%22E%22%20+%20parts%2C%20%22htt" ascii
    $s15 = "  parent[rlocalProtocol + \"un\"](merge);" fullword ascii
    $s16 = "function unbind(matchExpr, rparentsprev) {" fullword ascii
    $s17 = "function charCode(inspectPrefiltersOrTransports) {" fullword ascii
    $s18 = "function obj(extra, compile) {" fullword ascii
    $s19 = "  unbind(window, overflowX);" fullword ascii
    $s20 = "   protocol[keyCode + \"n\" + suffix]();" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}