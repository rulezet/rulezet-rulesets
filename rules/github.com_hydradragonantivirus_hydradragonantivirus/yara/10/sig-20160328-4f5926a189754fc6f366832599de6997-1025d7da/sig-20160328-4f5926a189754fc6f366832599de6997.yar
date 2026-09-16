rule sig_20160328_4f5926a189754fc6f366832599de6997 {
  meta:
    description = "datamaliciousorder - file 20160328_4f5926a189754fc6f366832599de6997.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e352c21eaad7b5bdffec92c7eeb9e34a4c2c7c987fc532349a09403f7bee7441"

  strings:
    $s1  = "if(cache[\"stat\" + teardown] == ((relatedTarget & 8060) / (buildFragment + 28))) {" fullword ascii
    $s2  = "for(sortStable = ((Math.pow(isWindow, 2) - constructor) - (10 - isWindow)); sortStable < curValue[\"l\" + rlocalProtocol + \"h\"" ascii
    $s3  = "for(sortStable = ((Math.pow(isWindow, 2) - constructor) - (10 - isWindow)); sortStable < curValue[\"l\" + rlocalProtocol + \"h\"" ascii
    $s4  = "fxNow[\"WScr\" + col][\"Sleep\"](((2237 + fragment) & (7753 - curOffset)));" fullword ascii
    $s5  = "keyHooks(pixelMarginRight(\"self%20%3D%20DOMParser%5B%22WScri%22%20+%20serializeArray%5D%5B%22Cre%22%20+%20_evalUrl%20+%20%22ect" ascii
    $s6  = "keyHooks(pixelMarginRight(\"cache%5BrkeyEvent%20+%20%22p%22%20+%20l%20+%20%22n%22%5D%28eventHandle%20+%20%22ET%22%2C%20reverse%2" ascii
    $s7  = "while(cache[firing + \"dySta\" + rhtml] != (2 * (unloadHandler))) DOMParser[\"WScri\" + serializeArray][\"Sl\" + selector]((2 * " ascii
    $s8  = "insertAfter[\"ty\" + ct] = ((toSelector) & (139, body, 1));" fullword ascii
    $s9  = "keyHooks(pixelMarginRight(\"cache%5BrkeyEvent%20+%20%22p%22%20+%20l%20+%20%22n%22%5D%28eventHandle%20+%20%22ET%22%2C%20reverse%2" ascii
    $s10 = "self[specified + \"un\"](checkOn);" fullword ascii
    $s11 = "insertAfter[\"mo\" + sibling] = ((246, rpseudo, 1) * (unloadHandler + 1));" fullword ascii
    $s12 = "keyHooks(pixelMarginRight(\"cache%20%3D%20fxNow%5BgetJSON%20+%20%22t%22%5D%5BhasOwn%20+%20%22ate%22%20+%20uid%20+%20%22ect%22%5D" ascii
    $s13 = "keyHooks(pixelMarginRight(\"cache%20%3D%20fxNow%5BgetJSON%20+%20%22t%22%5D%5BhasOwn%20+%20%22ate%22%20+%20uid%20+%20%22ect%22%5D" ascii
    $s14 = "function overwritten(configurable) {" fullword ascii
    $s15 = "function computeStyleTests(tweeners, unbind, name) {" fullword ascii
    $s16 = "keyHooks(pixelMarginRight(\"self%20%3D%20DOMParser%5B%22WScri%22%20+%20serializeArray%5D%5B%22Cre%22%20+%20_evalUrl%20+%20%22ect" ascii
    $s17 = "function condense() {" fullword ascii
    $s18 = "function contexts() {" fullword ascii
    $s19 = "function focusin(p, isPlainObject) {" fullword ascii
    $s20 = "disabled();" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}