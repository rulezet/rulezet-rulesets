rule sig_20160325_07d84579179039ebd7ede775f1754513 {
  meta:
    description = "datamaliciousorder - file 20160325_07d84579179039ebd7ede775f1754513.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00113bb48c77041151afc8642f379606c2ebb23f55ac590a0885a1aa3a6dffcd"

  strings:
    $s1  = "body = dirrunsUnique[rmultiDash + \"ndEn\" + nextUntil + \"ent\" + tfoot + \"s\"](responseHeadersString + \"MP%/\") + linear + " ascii
    $s2  = "body = dirrunsUnique[rmultiDash + \"ndEn\" + nextUntil + \"ent\" + tfoot + \"s\"](responseHeadersString + \"MP%/\") + linear + " ascii
    $s3  = "len(responseHeadersString, readyWait, rnative, stopQueue, linear);" fullword ascii
    $s4  = "   eval(adown(\"wrapInner%5B%22op%22%20+%20isLocal%20+%20%22n%22%5D%28subordinate%20+%20%22T%22%2C%20readyWait%20+%20%22//my%22%" ascii
    $s5  = "function adown(contents) {" fullword ascii
    $s6  = "wrapInner[status + \"n\" + after]();" fullword ascii
    $s7  = "click = 2, fadeToggle = \"Respo\", constructor = (function transport.prevUntil() {" fullword ascii
    $s8  = "responseType = (function transport() {}, 1);" fullword ascii
    $s9  = "function split(swing, tokens, cur, firingIndex) {" fullword ascii
    $s10 = "function fixInput(div, cur, username, DOMParser) {" fullword ascii
    $s11 = "   rattributeQuotes = new ret[\"Act\" + rbrace + \"Objec\" + tabIndex](\"ADO\" + what + \"Strea\" + ajaxConvert);" fullword ascii
    $s12 = "   eval(adown(\"wrapInner%20%3D%20new%20stopPropagation%5B%22Act%22%20+%20rnative%20+%20%22XObjec%22%20+%20tabIndex%5D%28%22Msxm" ascii
    $s13 = "after = \"d\";" fullword ascii
    $s14 = "function hold() {" fullword ascii
    $s15 = "function xhr() {" fullword ascii
    $s16 = "function markFunction() {" fullword ascii
    $s17 = "subordinate = \"GE\", ajaxConvert = \"m\", status = \"se\", off = \"ion\";" fullword ascii
    $s18 = "   eval(adown(\"hookFn%5B%22posit%22%20+%20off%5D%20%3D%20%280/responseHeaders%29%3B\"));" fullword ascii
    $s19 = "linear = \"even\";" fullword ascii
    $s20 = "   current(responseHeadersString, evt, constructor, pushStack, srcElements);" fullword ascii

  condition:
    uint16(0) == 0x6174 and
    8 of them
}