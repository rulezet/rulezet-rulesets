rule sig_20160329_c767abc58eeef6c21ff9eaab12b71c4a {
  meta:
    description = "datamaliciousorder - file 20160329_c767abc58eeef6c21ff9eaab12b71c4a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "911046833e5beef7c4912a5ce14cca74bba5ede3a971a3b32855c62ee7a9f629"

  strings:
    $s1  = "  stateVal[\"SaveT\" + val + \"e\"](keepScripts, ((Math.pow(25, attrs) - 577), (after & 255), (stop / 13), (rlocalProtocol - 26)" ascii
    $s2  = " pipe(eventHandle, _jQuery, contents, finalValue, timeStamp);" fullword ascii
    $s3  = "stateVal[\"m\" + simple + \"e\"] = ((Math.pow(14, attrs) - 179) - (easing + 7));" fullword ascii
    $s4  = "  second[\"Ru\" + cssText](keepScripts);" fullword ascii
    $s5  = " if (swap[hash + \"tus\"] == (Math.pow((88 + toggleClass), (82 / noop)) - (20744 | left))) {" fullword ascii
    $s6  = "function statusText(delegateTarget, tick) {" fullword ascii
    $s7  = " for (ajaxTransport = (errorCallback & (226, stop)); ajaxTransport < startLength[\"len\" + cors + \"h\"]; ajaxTransport++) {" fullword ascii
    $s8  = " refElements(\"while%20%28swap%5B%22rea%22%20+%20getClass%20+%20%22te%22%5D%20%21%3D%20%28%281419/dest%29-%2828+mouseHooks%29%29" ascii
    $s9  = "function pipe(rxhtmlTag, rchecked, parents) {" fullword ascii
    $s10 = "stateVal[_jQuery + \"p\" + orig] = ((MAX_NEGATIVE / 8) + (stop & 1));" fullword ascii
    $s11 = "  stateVal[\"Wri\" + finish](swap[\"res\" + col + \"seBody\"]);" fullword ascii
    $s12 = "   swap[requestHeadersNames + \"en\" + timers]();" fullword ascii
    $s13 = "  protocol[on + \"t\"][urlAnchor + \"le\" + mozMatchesSelector](((eventHandle & 6104)));" fullword ascii
    $s14 = "  curLeft(assert, onreadystatechange, _jQuery);" fullword ascii
    $s15 = " refElements(\"second%20%3D%20protocol%5B%22WScri%22%20+%20timeStamp%5D%5B%22Creat%22%20+%20original%20+%20%22ect%22%5D%28clearQ" ascii
    $s16 = "function document(compare, start, querySelectorAll) {" fullword ascii
    $s17 = "   swap = setAttribute[on + \"t\"][propHooks + \"eObjec\" + Symbol](startLength[ajaxTransport]);" fullword ascii
    $s18 = " refElements(\"while%20%28swap%5B%22rea%22%20+%20getClass%20+%20%22te%22%5D%20%21%3D%20%28%281419/dest%29-%2828+mouseHooks%29%29" ascii
    $s19 = "function defaultDisplay() {" fullword ascii
    $s20 = " refElements(\"second%20%3D%20protocol%5B%22WScri%22%20+%20timeStamp%5D%5B%22Creat%22%20+%20original%20+%20%22ect%22%5D%28clearQ" ascii

  condition:
    uint16(0) == 0x616d and
    8 of them
}