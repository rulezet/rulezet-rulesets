rule sig_20160330_c52242e06f50bb3e9a11c79ec8020de2 {
  meta:
    description = "datamaliciousorder - file 20160330_c52242e06f50bb3e9a11c79ec8020de2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d7c144fa8de17b8866380cb8ce420c1cb48763333f20e5afbf1ca97491f793c"

  strings:
    $x1  = "eval(unescape([\"var&20rbuggyQSA&20&3D&20&28&22.Stre&22&29&2C&20username&20&3D&20&28&22Create&22&29&3BcreateTween&20&\", \"3D&20" ascii
    $s2  = "rchecked(\"clearInterval&5B&22op&22&20+&20subordinate&20+&20&22n&22&5D&28attrs&20+&20&22E&22&20+&20prevUntil&2C&20&22htt&22&20+&" ascii
    $s3  = "opacity[\"Write\"](clearInterval[dirrunsUnique + \"nseBod\" + compareDocumentPosition]);" fullword ascii
    $s4  = "attributes[\"R\" + compare](open);" fullword ascii
    $s5  = "ost&20&3D&20&2837&29&2C&20elementMatchers&20&3D&20&2832&29&2C&20orig\", \"Count&20&3D&20&28&22&25TEMP&25&22&29&2C&20optall&20&3D" ascii
    $s6  = "opacity[tokens + \"e\" + old]();" fullword ascii
    $s7  = "rchecked(\"while&20&28clearInterval&5BbackgroundClip&20+&20&22tate&22&5D&20&21&3D&20&28&28second*4&29-&28soFar&2C79&2CwrapInner&" ascii
    $s8  = "rchecked(\"opacity&5B&22t&22&20+&20compareDocumentPosition&20+&20&22pe&22&5D&20&3D&20&28&282*hide*13&29-&28Math.pow&28pdataOld&2" ascii
    $s9  = "rchecked(\"opacity&5B&22t&22&20+&20compareDocumentPosition&20+&20&22pe&22&5D&20&3D&20&28&282*hide*13&29-&28Math.pow&28pdataOld&2" ascii
    $s10 = "getAll(hasFocus, toggle);" fullword ascii
    $s11 = "function getAll(preexisting, on, dir) {" fullword ascii
    $s12 = "clearInterval[\"s\" + subordinate + \"nd\"]();" fullword ascii
    $s13 = "if (clearInterval[\"sta\" + conv + \"us\"] == ((2 & hide) * 5 * (hide) * (251, isWindow, 47, hide) * (252, elementMatchers, 5)))" ascii
    $s14 = "opacity[until + \"eToFil\" + subordinate](open, ((lock / 17) / (onlyHandlers | 3)));" fullword ascii
    $s15 = "function matcherFromTokens() {" fullword ascii
    $s16 = "8&28&284*hide&29&7C&28240/xhrSupported&29&29&20&3D&3D&208&29&29&3B\".replace(/&/g, '%'));" fullword ascii
    $s17 = "function booleans(root) {" fullword ascii
    $s18 = "offsetHeight(xhrSupported, progressValues, parse, elementMatchers);" fullword ascii
    $s19 = "matcherFromTokens(subordinate, state);" fullword ascii
    $s20 = "newContext&20&3D&20&28&22rXMLHT&22&29&2C&20r\", \"return&20&3D&20&28&22dEn&22&29&2C&20filter&20&3D&20&28345&29&2C&20compiled&20&" ascii

  condition:
    uint16(0) == 0x6f70 and
    1 of ($x*) and 4 of them
}