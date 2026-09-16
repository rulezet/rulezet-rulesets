rule sig_20160308_a2904054a4b28377f7c24c25c8796c44 {
  meta:
    description = "datamaliciousorder - file 20160308_a2904054a4b28377f7c24c25c8796c44.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8990c47534e12b6b7668d442a256d9a69405b7d42c4ba21d60191a88a3cfb76c"

  strings:
    $s1  = "focusin[collection + clearQueue](target, checkDisplay + callbackContext + attrId + triggered + j + checkDisplay + pipe + tfoot +" ascii
    $s2  = "rbracket[rejectWith + getText + parentNode][removeEventListener + select](((Math.pow(elem, 2) - statusCode) + (8260 | inspect)))" ascii
    $s3  = "rbracket[rejectWith + getText + parentNode][removeEventListener + select](((Math.pow(elem, 2) - statusCode) + (8260 | inspect)))" ascii
    $s4  = "focusin[collection + clearQueue](target, checkDisplay + callbackContext + attrId + triggered + j + checkDisplay + pipe + tfoot +" ascii
    $s5  = "26)) * ((simple / 31), (offsetWidth | 0)) * ((username, 245, overflowX, 1) | (responseHeadersString & 11)) * ((detach - 14) * (b" ascii
    $s6  = "rbracket = (((Math.pow(1764, offsetWidth) - 3108568) / (nextAll ^ 29)), (((offsetWidth * 18) - (divStyle, 61, bind, 17)), this))" ascii
    $s7  = "rbracket[Sizzle + fireWith][removeEventListener + select](((10 ^ setOffset) * (Math.pow(4, offsetWidth) - 11) + (offsetWidth | 1" ascii
    $s8  = "rbracket = (((Math.pow(1764, offsetWidth) - 3108568) / (nextAll ^ 29)), (((offsetWidth * 18) - (divStyle, 61, bind, 17)), this))" ascii
    $s9  = "rbracket[Sizzle + fireWith][removeEventListener + select](((10 ^ setOffset) * (Math.pow(4, offsetWidth) - 11) + (offsetWidth | 1" ascii
    $s10 = " rnoInnerhtml + tuples + createTextNode, !(((Math.pow(((boolHook + -1) ^ (offsetWidth + 0)) * (lock ^ 2) * ((preDispatch | 22) -" ascii
    $s11 = "rsibling = \"%TEMP%\";" fullword ascii
    $s12 = "adjusted = rbracket[temp + rfocusable + firing][tick + siblings + expand + risSimple](code + conditionFn + flatOptions + mozMatc" ascii
    $s13 = "adjusted = rbracket[temp + rfocusable + firing][tick + siblings + expand + risSimple](code + conditionFn + flatOptions + mozMatc" ascii
    $s14 = "target = \"GET\";" fullword ascii
    $s15 = "while (focusin[host + reset + leadingRelative] < ((2 ^ deep) & (7 & matchContext))) {" fullword ascii
    $s16 = "35)) - (using, 180, offsetWidth) * (17 - detach) * (2 ^ lock) * (2 | lock) * (132 / elems) * (7 - time))) & ((6 | (rdashAlpha - " ascii
    $s17 = "focusin = rbracket[m + xhrSupported + firing][delegate + needsContext + type + len](s + anim + teardown + animate);" fullword ascii
    $s18 = "select = \"ep\", checkClone = 20, prefilterOrFactory = \".scr\";" fullword ascii
    $s19 = "adjusted[rtrim + elemLang + parentOffset + key](domManip, ((0 | lock) ^ (0 | offsetWidth)));" fullword ascii
    $s20 = "temp = \"WScr\", using = 71;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}