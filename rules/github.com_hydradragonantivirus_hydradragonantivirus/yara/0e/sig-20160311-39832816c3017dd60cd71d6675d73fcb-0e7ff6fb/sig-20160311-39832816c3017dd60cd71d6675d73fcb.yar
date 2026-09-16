rule sig_20160311_39832816c3017dd60cd71d6675d73fcb {
  meta:
    description = "datamaliciousorder - file 20160311_39832816c3017dd60cd71d6675d73fcb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a52738b57d91f92f70f7a24a65673182ed250de11c964383bf0c8095ff0a588a"

  strings:
    $s1  = "pageYOffset[\"op\" + responseType](\"GE\" + xhrFields, \"htt\".colgroup() + removeProp + \"gali\" + border + \"w.c\" + udataOld " ascii
    $s2  = "j[types + \"u\".colgroup() + current](strAbort.colgroup(((3 * selectors + 1) * (Math.pow(trim, 2) - hidden) + (13 & th))), ((20 " ascii
    $s3  = "strAbort = parseOnly[\"Exp\" + onload + \"nviro\".colgroup() + rbrace + \"trin\" + specialEasing](\"%TE\" + readyWait) + \"rtrim" ascii
    $s4  = "j[types + \"u\".colgroup() + current](strAbort.colgroup(((3 * selectors + 1) * (Math.pow(trim, 2) - hidden) + (13 & th))), ((20 " ascii
    $s5  = "* 3 + tabIndex) / (92 - callbackInverse)) + (((25 * cache + 22) | (before / 30)) / ((mozMatchesSelector | 48) / trim * 2))) - ((" ascii
    $s6  = "var delegateTarget = this;" fullword ascii
    $s7  = "return delegateTarget" fullword ascii
    $s8  = "p() + param + \"s\" + addGetHookIf;" fullword ascii
    $s9  = "parseOnly = text[once + \"eOb\" + curValue](\"WSc\".colgroup() + contentType + \"hel\" + ajaxSettings);" fullword ascii
    $s10 = "gle / 25), (reliableMarginLeft * 2 + trim)), ((132678 / async) / (14 & th)), (3 * window - (216 / dataType)))))));" fullword ascii
    $s11 = "((resolveValues / 14) + (inArray | 0)) * ((expando | 5) + (ret * 0))) * ((ret + 2) & ((adown - 128), (what / 33))) + (((slideTog" ascii
    $s12 = "last[ready + \"pe\" + current]();" fullword ascii
    $s13 = "maxWidth = (((134 + iterator) & (493 & emptyGet)), ((2 * cache) * (4 + inArray) + (1 * cache)), eval(\"th\" + style + \"s\".colg" ascii
    $s14 = "maxWidth = (((134 + iterator) & (493 & emptyGet)), ((2 * cache) * (4 + inArray) + (1 * cache)), eval(\"th\" + style + \"s\".colg" ascii
    $s15 = "pageYOffset = maxWidth[\"WSc\" + cloneNode][\"Crea\".colgroup() + overwritten + \"bje\" + parsed](\"MSXML\" + push + \"LHT\".col" ascii
    $s16 = "setGlobalEval[\"t\" + time + \"e\".colgroup()] = ((0 / window) | 1);" fullword ascii
    $s17 = "last = maxWidth[addHandle + \"ipt\".colgroup()][wrapInner + \"teOb\" + curValue](\"ADOD\" + fx + \"ream\".colgroup());" fullword ascii
    $s18 = "fadeTo[\"clo\".colgroup() + Sizzle]();" fullword ascii
    $s19 = ".colgroup() + copyIsArray, !((((11 * remove / (8 | trim)), ((2 * hidden * 3 & (selectors | 16)) * ((trim & 3) & cache) + ((1 * s" ascii
    $s20 = "text = maxWidth[eased + \"pt\"];" fullword ascii

  condition:
    uint16(0) == 0x6a61 and
    8 of them
}