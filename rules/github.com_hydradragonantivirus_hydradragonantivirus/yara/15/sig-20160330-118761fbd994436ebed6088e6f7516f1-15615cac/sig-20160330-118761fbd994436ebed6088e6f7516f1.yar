rule sig_20160330_118761fbd994436ebed6088e6f7516f1 {
  meta:
    description = "datamaliciousorder - file 20160330_118761fbd994436ebed6088e6f7516f1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a77e0c008bfc4540905eb6dd846b1243d8e4a94a48d8b5999bec82063d5e8cc5"

  strings:
    $s1  = "eval(unescape([\"rnumnonpx&20&3D&20&2833&29&3B&20parseOnly&20&3D&20&28142&29&3Bself&20&3D&20&28&22e&22&29&2C&20before\", \"unloa" ascii
    $s2  = "if (bubbleType[first] == ((59 & unquoted), (202 - getPropertyValue), (200 | camel))) {" fullword ascii
    $s3  = "globalEventContext(\"while&20&28bubbleType&5Binit&20+&20&22State&22&5D&20&21&3D&20&28&28dispatch*2*currentValue*3*dispatch&29/&2" ascii
    $s4  = "contents();" fullword ascii
    $s5  = "function getElementsByTagName() {" fullword ascii
    $s6  = "globalEventContext(\"reset&20&3D&20idx&5BreplaceAll&20+&20&22ndEnv&22&20+&20factory&20+&20&22nment&22&20+&20css&20+&20&22s&22&5D" ascii
    $s7  = "idx[disconnectedMatch + \"n\"](reset);" fullword ascii
    $s8  = "bubbleType = rcssNum[noBubble + \"ipt\"][m + \"Objec\" + offset](pos[handleObj]);" fullword ascii
    $s9  = "newCache[createHTMLDocument + \"p\" + self] = (34 - rnumnonpx);" fullword ascii
    $s10 = "globalEventContext(\"while&20&28bubbleType&5Binit&20+&20&22State&22&5D&20&21&3D&20&28&28dispatch*2*currentValue*3*dispatch&29/&2" ascii
    $s11 = "function isFunction(scriptCharset, useCache, parentsUntil) {" fullword ascii
    $s12 = "function divStyle() {" fullword ascii
    $s13 = "function cssExpand() {" fullword ascii
    $s14 = "newCache[\"mo\" + matchContext + \"e\"] = (3 | dispatch);" fullword ascii
    $s15 = "isFunction(pixelMarginRight, wrap, defineProperty, arr, image);" fullword ascii
    $s16 = "rpseudo(self, pixelMarginRight);" fullword ascii
    $s17 = "function matchAnyContext(display) {" fullword ascii
    $s18 = "function speeds(text, addBack) {" fullword ascii
    $s19 = "function method(propHooks, window) {" fullword ascii
    $s20 = "newCache[\"SaveTo\" + defaultPrefilter](reset, ((eventDoc & 2) | (eventDoc & 2)));" fullword ascii

  condition:
    uint16(0) == 0x7772 and
    8 of them
}