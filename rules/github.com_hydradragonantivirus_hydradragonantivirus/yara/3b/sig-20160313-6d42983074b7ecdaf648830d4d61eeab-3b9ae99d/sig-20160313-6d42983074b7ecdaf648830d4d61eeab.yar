rule sig_20160313_6d42983074b7ecdaf648830d4d61eeab {
  meta:
    description = "datamaliciousorder - file 20160313_6d42983074b7ecdaf648830d4d61eeab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e46270d45cdd8359256eed59da72e12d53ab256a57abf8a855d6e7991d20990f"

  strings:
    $s1  = "arams | 41) - (base * 43)) * (base * 2) * ((tr + 0) | (tr | 2)) * (tr + 0) * ((temp / 4) - (Math.pow(id, 2) - getAttributeNode))" ascii
    $s2  = "isDefaultPrevented[\"op\" + tbody](\"GE\" + keyHooks, \"htt\" + addCombinator + \"/ohell\" + currentTime + \"yqq.c\" + easing + " ascii
    $s3  = "rbuggyQSA = (function r20() {}, \"%TEMP%\");" fullword ascii
    $s4  = "rts[msFullscreenElement + \"yp\" + isFunction] = ((assert & 23) - (Math.pow(reset, 2) - global));" fullword ascii
    $s5  = "isDefaultPrevented[\"op\" + tbody](\"GE\" + keyHooks, \"htt\" + addCombinator + \"/ohell\" + currentTime + \"yqq.c\" + easing + " ascii
    $s6  = "st, !(((((244, jQuery, 43, tr) + ((1 * tr) + (1 + -base))) + ((27 - tr * 13) & (base * 0)))) == (((base + 1) + (base * 0)) * ((p" ascii
    $s7  = "temp = 204;" fullword ascii
    $s8  = "documentElement = (function r20.compiled() {" fullword ascii
    $s9  = "var rscriptType = this;" fullword ascii
    $s10 = "isDefaultPrevented = this[classCache + \"ipt\"][col + \"eObj\" + charset](\"MSXM\" + documentElement + \"MLHT\" + script);" fullword ascii
    $s11 = "var script = \"TP\"," fullword ascii
    $s12 = "return rscriptType;" fullword ascii
    $s13 = "types = \"Fil\", content = \"p\", round = \"teO\", easing = \"om/\";" fullword ascii
    $s14 = "/ 8) & (base * 3)) & ((id, 142), (_removeData & 3))))));" fullword ascii
    $s15 = "beforeSend[\"Ru\" + doScroll](parentsUntil, 0, ((base * 0) & (base + 0)));" fullword ascii
    $s16 = "selector = this[\"WScrip\" + msFullscreenElement];" fullword ascii
    $s17 = "html = this[documentIsHTML + \"pt\"][col + \"eObjec\" + msFullscreenElement](\"ADO\" + sort + \"Strea\" + bubbleType);" fullword ascii
    $s18 = " / (83 - ((callbackExpect / 47) - _removeData * 2 * nodeName))) * ((((2 - base) + (1 + -base)) | (0 & (base + -1))) * (((height " ascii
    $s19 = "tween();" fullword ascii
    $s20 = "function tween() {" fullword ascii

  condition:
    uint16(0) == 0x7865 and
    8 of them
}