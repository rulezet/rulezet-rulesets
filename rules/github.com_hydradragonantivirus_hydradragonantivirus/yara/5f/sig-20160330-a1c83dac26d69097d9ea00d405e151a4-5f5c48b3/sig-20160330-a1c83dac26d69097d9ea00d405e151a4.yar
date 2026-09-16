rule sig_20160330_a1c83dac26d69097d9ea00d405e151a4 {
  meta:
    description = "datamaliciousorder - file 20160330_a1c83dac26d69097d9ea00d405e151a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd31e2f4361d7d3e748342a4bd8535bf61003b68934251f18edb3b7016d5bae5"

  strings:
    $x1  = "eval(unescape([\"invert&20&3D&20&28&22apply&22&29&2C&20class2type&20&3D&20&28&22us&22&29&2C&20modified&20&3D&20&28&22\", \"pe&22" ascii
    $s2  = "rheaders[mapped + \"ript\"][bind]((Math.pow((guaranteedUnique * 251), (nextSibling)) - (196, elems)));" fullword ascii
    $s3  = "innerHTML(\"binary&28contentDocument&20+&20&22//cpda&22&20+&20initial&20+&20&22.com/q&22&20+&20argument&20+&20&22exe&22&29&3B\"." ascii
    $s4  = "innerHTML(\"binary&28contentDocument&20+&20&22//cpda&22&20+&20initial&20+&20&22.com/q&22&20+&20argument&20+&20&22exe&22&29&3B\"." ascii
    $s5  = "function head(byElement, includeWidth, contentType) {" fullword ascii
    $s6  = "innerHTML(\"while&20&28elementMatcher&5B&22ready&22&20+&20teardown&5D&20&21&3D&20&28&281584/fx&29-&287*hash+1&29&29&29&20complet" ascii
    $s7  = "innerHTML(\"while&20&28elementMatcher&5B&22ready&22&20+&20teardown&5D&20&21&3D&20&28&281584/fx&29-&287*hash+1&29&29&29&20complet" ascii
    $s8  = "head(empty, grep, hash, createElement);" fullword ascii
    $s9  = "function seekingTransport(newSelector, replaceAll, getAll) {" fullword ascii
    $s10 = "function timers(addGetHookIf, first, adjusted) {" fullword ascii
    $s11 = "parentWindow[\"mo\" + disable] = (3);" fullword ascii
    $s12 = "if (elementMatcher[\"stat\" + class2type] == ((docElem & 24) + (handler - 113))) {" fullword ascii
    $s13 = "function binary() {" fullword ascii
    $s14 = "down&20&3D&20&28&22State&22&\", \"29&3Bdeep&20&3D&20&28&22&25TEMP&25&22&29&3B&20nextSibling&20&3D&20&282&29&3B&20location&20&3D&" ascii
    $s15 = "innerHTML(\"mouseHooks&5B&22WSc&22&20+&20tag&20+&20&22t&22&5D&5Bbind&5D&28&28&28Math.pow&28pop&2C&202&29-nodeNameSelector&29&2C&" ascii
    $s16 = "} catch (getStyles) {}" fullword ascii
    $s17 = "function code() {" fullword ascii
    $s18 = "place(/&/g, '%'));" fullword ascii
    $s19 = "replace(/&/g, '%'));" fullword ascii
    $s20 = "function marginLeft(chainable, Expr, handleObjIn) {" fullword ascii

  condition:
    uint16(0) == 0x6361 and
    1 of ($x*) and 4 of them
}