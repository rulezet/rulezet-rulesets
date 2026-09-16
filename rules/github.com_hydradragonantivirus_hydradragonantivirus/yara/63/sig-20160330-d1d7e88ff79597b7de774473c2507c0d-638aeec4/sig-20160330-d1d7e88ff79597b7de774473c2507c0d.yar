rule sig_20160330_d1d7e88ff79597b7de774473c2507c0d {
  meta:
    description = "datamaliciousorder - file 20160330_d1d7e88ff79597b7de774473c2507c0d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05868d5a0ea0cb40a820000a51ba9c148bf5847fdb91bdaa26f4898a249fb927"

  strings:
    $x1  = "eval(unescape([\"ofType&20&3D&20&28&22.She&22&29&3B&20focusin&20&3D&20&28&22ream&22&29&3B&20preDispatch&20&3D&20&2820\", \"&29&3" ascii
    $s2  = "if (getAll[unbind + \"us\"] == ((Math.pow(stopImmediatePropagation, 2) - specialEasing) + (35 - rhash))) {" fullword ascii
    $s3  = "getAll = originAnchor[getElementsByTagName + \"ipt\"][hasCompare + \"ateOb\" + iframe](disable[fx]);" fullword ascii
    $s4  = "keys(\"while&20&28getAll&5B&22ready&22&20+&20noop&5D&20&21&3D&20&28&28orig/16&29*&28step+0&29&29&29&20random&5B&22WScri&22&20+&2" ascii
    $s5  = "keys(\"while&20&28getAll&5B&22ready&22&20+&20noop&5D&20&21&3D&20&28&28orig/16&29*&28step+0&29&29&29&20random&5B&22WScri&22&20+&2" ascii
    $s6  = "hold[\"R\" + keepScripts](curElem);" fullword ascii
    $s7  = "getAll[\"s\" + next + \"n\" + n]();" fullword ascii
    $s8  = "msg[createTween + \"eToFi\" + prototype](curElem, ((21 - noConflict) + (0 / unloadHandler)));" fullword ascii
    $s9  = "for (fx = ((siblingCheck - 13) + -unloadHandler); fx < disable[rjsonp + \"th\"]; fx++) {" fullword ascii
    $s10 = "lang(when, interval, password, siblingCheck, adjusted);" fullword ascii
    $s11 = "keys(\"disable&20&3D&20&5B&22Msx&22&20+&20cors&20+&20&22Ser&22&20+&20opts&20+&20&22LHTTP.&22&20+&20keyHooks&2C&20&22Msx&22&20+&2" ascii
    $s12 = "function lang(get, text) {" fullword ascii
    $s13 = "keys(\"disable&20&3D&20&5B&22Msx&22&20+&20cors&20+&20&22Ser&22&20+&20opts&20+&20&22LHTTP.&22&20+&20keyHooks&2C&20&22Msx&22&20+&2" ascii
    $s14 = "originAnchor = random = isSimulated = seekingTransport = append.toArray();" fullword ascii
    $s15 = "traditional(focusin, keyHooks);" fullword ascii
    $s16 = "display&20&3D&20&28113&29&2C&20interval&20&3D&20&28&22LHTTP&22&29&3Bvar&20showHide&20&3D&20&28&22pe&\", \"22&29&2C&20initial&20&" ascii
    $s17 = "function keys(parseOnly) {" fullword ascii
    $s18 = "function uniqueSort() {" fullword ascii
    $s19 = "function dataShow() {" fullword ascii
    $s20 = "function destElements(nextAll) {" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    1 of ($x*) and 4 of them
}