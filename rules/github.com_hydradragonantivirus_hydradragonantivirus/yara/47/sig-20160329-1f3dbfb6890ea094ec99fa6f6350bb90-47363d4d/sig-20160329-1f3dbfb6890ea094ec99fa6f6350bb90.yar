rule sig_20160329_1f3dbfb6890ea094ec99fa6f6350bb90 {
  meta:
    description = "datamaliciousorder - file 20160329_1f3dbfb6890ea094ec99fa6f6350bb90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65d36435edbfc711165125c06098eaec283e08dfff4320a695514c64ac6f24f7"

  strings:
    $s1  = "ct[\"WScrip\" + fire][\"Sle\" + tuple](((353 - write), (105 + getElementsByName), (31 & window), (210000 / tokenize)));" fullword ascii
    $s2  = "scripts[rcleanScript + \"pe\" + opacity]();" fullword ascii
    $s3  = "valHooks = count[prop + \"t\"][preMap + \"ateOb\" + keepScripts](e[rsubmittable]);" fullword ascii
    $s4  = "scripts[\"SaveT\" + MAX_NEGATIVE](configurable, ((winnow, 233, callbackName) | (1 * callbackName)));" fullword ascii
    $s5  = "conv2(\"while%20%28valHooks%5Bend%20+%20%22ySta%22%20+%20evt%5D%20%21%3D%20%28Math.pow%28%28117/rlocalProtocol%29%2C%202%29-%28r" ascii
    $s6  = "if(valHooks[location + \"us\"] == ((Math.pow(187, callbackName) - 34767) & (preferredDoc - 70))) {" fullword ascii
    $s7  = "apply(optionSet, tokenize, keyCode);" fullword ascii
    $s8  = "cssShow(addEventListener, cache, keepScripts);" fullword ascii
    $s9  = "valHooks[attributes + \"e\" + opacity + \"d\"]();" fullword ascii
    $s10 = "function unique(maxWidth, split, rootjQuery) {" fullword ascii
    $s11 = "r20(transport);" fullword ascii
    $s12 = "conv2(\"count%5B%22WScr%22%20+%20dirrunsUnique%5D%5B%22S%22%20+%20second%5D%28%28%28rscriptTypeMasked*5*callbackName*2*rscriptTy" ascii
    $s13 = "conv2(\"count%5B%22WScr%22%20+%20dirrunsUnique%5D%5B%22S%22%20+%20second%5D%28%28%28rscriptTypeMasked*5*callbackName*2*rscriptTy" ascii
    $s14 = "conv2(\"while%20%28valHooks%5Bend%20+%20%22ySta%22%20+%20evt%5D%20%21%3D%20%28Math.pow%28%28117/rlocalProtocol%29%2C%202%29-%28r" ascii
    $s15 = "unique();" fullword ascii
    $s16 = "function curTop() {" fullword ascii
    $s17 = "function conv2(returnFalse) {" fullword ascii
    $s18 = "function apply(origCount) {" fullword ascii
    $s19 = "function r20(onload) {" fullword ascii
    $s20 = "function disable(close, wrap, genFx) {" fullword ascii

  condition:
    uint16(0) == 0x6166 and
    8 of them
}