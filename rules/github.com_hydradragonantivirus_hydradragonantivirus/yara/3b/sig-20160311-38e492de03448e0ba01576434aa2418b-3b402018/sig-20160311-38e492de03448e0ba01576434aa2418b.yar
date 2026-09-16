rule sig_20160311_38e492de03448e0ba01576434aa2418b {
  meta:
    description = "datamaliciousorder - file 20160311_38e492de03448e0ba01576434aa2418b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c33ca32c70905662bb648e7eed9e71512725aa988119c4bc8b4130b63afccacc"

  strings:
    $s1  = "fromCharCode[globalEval + \"pe\" + fadeTo](\"G\" + idx, \"http:/\".remaining() + clearInterval + \"28.21\" + triggerHandler + \"" ascii
    $s2  = "rheader = binary[\"Expa\" + pageX + \"viro\".remaining() + camelKey + \"ntStri\" + firstChild](\"%TEM\" + tokens) + \"cl\".remai" ascii
    $s3  = "stopOnFalse[close + \"n\"](rheader.remaining(((Math.pow(preMap, 2) - pointerenter) / 37)), ((expando, 165, active, 0) / (tuples " ascii
    $s4  = "stopOnFalse[close + \"n\"](rheader.remaining(((Math.pow(preMap, 2) - pointerenter) / 37)), ((expando, 165, active, 0) / (tuples " ascii
    $s5  = "rheader = binary[\"Expa\" + pageX + \"viro\".remaining() + camelKey + \"ntStri\" + firstChild](\"%TEM\" + tokens) + \"cl\".remai" ascii
    $s6  = "unshift = (((Math.pow(63, scrollTop) - 3899) - (tuples * 0)), ((always, 203, uid, 54) - (Math.pow(originalEvent, 2) - disable))," ascii
    $s7  = "unshift = (((Math.pow(63, scrollTop) - 3899) - (tuples * 0)), ((always, 203, uid, 54) - (Math.pow(originalEvent, 2) - disable))," ascii
    $s8  = "low + \"o8i76\".remaining() + transport + \"4\", !(((((1 * tuples)) + ((7 / position) * (44 - outermost))) * (1 + scrollTop)) * " ascii
    $s9  = "alEventContext))) - (((93 & handlers) * (14 & addCombinator) + (181, removeAttr, 17, mimeType)) / (2 * (response - 12) + tuples)" ascii
    $s10 = "scrollTop = 2, tuples = 1, targets = 8, handlers = 71, owner = \"Str\";" fullword ascii
    $s11 = "return + \".s\" + host + \"r\";" fullword ascii
    $s12 = "startTime = unshift[checked + \"ipt\".remaining()][contentType + \"teObj\" + clientLeft](\"ADODB.\" + owner + \"eam\".remaining(" ascii
    $s13 = ")) + ((((201, attrHooks, 45, proxy) + (1526 / hasDuplicate)) - ((592 - appendChild) / (29 - rhtml))), (((1 * expanded) | 2 * scr" ascii
    $s14 = "binary = left[\"Crea\" + udataOld + \"ject\".remaining()](checked + \"ipt.Sh\" + curCSSLeft);" fullword ascii
    $s15 = "host = \"c\";" fullword ascii
    $s16 = "curTop[caption + \"yp\" + preFilters] = ((255, hasDuplicate, 205, tuples) * (7 - cssProps));" fullword ascii
    $s17 = "left = unshift[\"WScr\" + defer];" fullword ascii
    $s18 = "adjustCSS[\"clo\" + trigger]();" fullword ascii
    $s19 = "(funescape, 2) - tbody)))) == ((((19 - hasDuplicate) * 2 * scrollTop * (88 / outermost) + ((128, globalEventContext) + (6 | glob" ascii
    $s20 = "fromCharCode[trigger + \"nd\"]();" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    8 of them
}