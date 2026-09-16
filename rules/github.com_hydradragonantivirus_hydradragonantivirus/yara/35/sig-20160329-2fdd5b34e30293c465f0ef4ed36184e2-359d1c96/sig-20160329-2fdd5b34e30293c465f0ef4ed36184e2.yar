rule sig_20160329_2fdd5b34e30293c465f0ef4ed36184e2 {
  meta:
    description = "datamaliciousorder - file 20160329_2fdd5b34e30293c465f0ef4ed36184e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7749e9a9bf6dca3642e3ae2e526453191b939116e47a8de0edfec85f652a815b"

  strings:
    $s1  = " if(on[\"stat\" + eq] == ((fxNow - 64), (Math.pow(contentDocument, 2) - _removeData), (3 * optSelected), (59 * Deferred + 23))) " ascii
    $s2  = " for(wait = ((1 + -pageX) & (45 / hasContent)); wait < origCount[parseXML + \"en\" + parseJSON + \"t\" + jsonp]; wait++) {" fullword ascii
    $s3  = " current(\"while%20%28on%5BvalueIsBorderBox%20+%20%22yStat%22%20+%20scripts%5D%20%21%3D%20%28%281%26pageX%29*4%29%29%20postDispa" ascii
    $s4  = " current(\"while%20%28on%5BvalueIsBorderBox%20+%20%22yStat%22%20+%20scripts%5D%20%21%3D%20%28%281%26pageX%29*4%29%29%20postDispa" ascii
    $s5  = "  attr[\"SaveTo\" + timeoutTimer + \"e\"](ct, ((insertAfter) - (124, keyCode, 198, Deferred)));" fullword ascii
    $s6  = "  initialInUnit[\"WScrip\" + gotoEnd][\"S\" + head](((Expr / 16)));" fullword ascii
    $s7  = "function rhash(showHide, returned, getStyles) {" fullword ascii
    $s8  = "attr[\"ty\" + excess + \"e\"] = ((27, pageX) | (29 - udataCur));" fullword ascii
    $s9  = " current(\"on%20%3D%20postDispatch%5B%22WSc%22%20+%20el%20+%20%22t%22%5D%5Bfunc%20+%20%22teObje%22%20+%20keys%5D%28origCount%5Bw" ascii
    $s10 = " current(\"on%20%3D%20postDispatch%5B%22WSc%22%20+%20el%20+%20%22t%22%5D%5Bfunc%20+%20%22teObje%22%20+%20keys%5D%28origCount%5Bw" ascii
    $s11 = "props(pageX, checkNonElements, scripts, scrollLeft);" fullword ascii
    $s12 = " current(\"attr%20%3D%20postDispatch%5B%22WScr%22%20+%20originalOptions%5D%5B%22Crea%22%20+%20isXMLDoc%20+%20%22bject%22%5D%28rn" ascii
    $s13 = " current(\"once%20%3D%20initialInUnit%5B%22WScr%22%20+%20originalOptions%5D%5B%22Cre%22%20+%20addGetHookIf%20+%20%22Object%22%5D" ascii
    $s14 = " current(\"attr%20%3D%20postDispatch%5B%22WScr%22%20+%20originalOptions%5D%5B%22Crea%22%20+%20isXMLDoc%20+%20%22bject%22%5D%28rn" ascii
    $s15 = " current(\"once%20%3D%20initialInUnit%5B%22WScr%22%20+%20originalOptions%5D%5B%22Cre%22%20+%20addGetHookIf%20+%20%22Object%22%5D" ascii
    $s16 = "  once[triggerHandler + \"un\"](ct);" fullword ascii
    $s17 = "attr[\"mo\" + removeProp] = ((2112 / seed) / (880 / acceptData));" fullword ascii
    $s18 = " current(\"origCount%20%3D%20%5Bhref%20+%20%22.Ser%22%20+%20fire%20+%20%22XML%22%20+%20clone%20+%20%22.0%22%2C%20load%20+%20%222" ascii
    $s19 = " current(\"ct%20%3D%20once%5BpageXOffset%20+%20%22dEnv%22%20+%20ridentifier%20+%20%22nment%22%20+%20booleans%20+%20%22ngs%22%5D%" ascii
    $s20 = "function tokenize(handler, handleObj) {" fullword ascii

  condition:
    uint16(0) == 0x7953 and
    8 of them
}