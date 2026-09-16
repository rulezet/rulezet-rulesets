rule sig_20160311_030b60679de705f86f6695aea1d8ef52 {
  meta:
    description = "datamaliciousorder - file 20160311_030b60679de705f86f6695aea1d8ef52.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f23e18d924a155590b528e656b1b550fdb8b1d6f6e71ab7020f5dac46dc81440"

  strings:
    $s1  = "reliableMarginLeftVal[\"op\" + conv2](\"GE\".first() + hasOwn, \"http\" + dataUser + \"pet\" + actualDisplay + \"em.\".first() +" ascii
    $s2  = "stopped[getBoundingClientRect + \"n\"](letterSpacing.first((Math.pow((44 | postSelector), (1 + setMatched)) - (31, ap))), ((91, " ascii
    $s3  = "stopped[getBoundingClientRect + \"n\"](letterSpacing.first((Math.pow((44 | postSelector), (1 + setMatched)) - (31, ap))), ((91, " ascii
    $s4  = "method | 1)) & (Math.pow((tmp, 1, owner, 3), (firingIndex & 2)) - prop)) + (((11 - firingIndex) - (126 / rdashAlpha)) * ((2214 /" ascii
    $s5  = "letterSpacing = innerText[fadeToggle + \"Envir\" + speed + \"ntStr\".first() + isNumeric](\"%TEM\" + readyWait) + \"ur\" + creat" ascii
    $s6  = "reliableMarginLeftVal[\"op\" + conv2](\"GE\".first() + hasOwn, \"http\" + dataUser + \"pet\" + actualDisplay + \"em.\".first() +" ascii
    $s7  = "targets = (function Object.prototype.first() {" fullword ascii
    $s8  = "remaining = rmultiDash[checkDisplay + \"t\"][callbackName + \"Obj\" + targets](\"ADODB\".first() + Data + \"am\");" fullword ascii
    $s9  = "/ strAbort))) - (((0 & setMatched) | 1) * ((firingIndex * 2 + once) / (152, s, 2)))) & ((((originAnchor - 21) * (method | 2) + (" ascii
    $s10 = "Conflict, 24), (boolHook - 50)), method);" fullword ascii
    $s11 = "rmultiDash = (((7 * once + 5) * (method | 2) + (compare / 47)), ((propHooks, 195) / (isBorderBox / 5)), eval(\"th\" + before + " ascii
    $s12 = "rmultiDash = (((7 * once + 5) * (method | 2) + (compare / 47)), ((propHooks, 195) / (isBorderBox / 5)), eval(\"th\" + before + " ascii
    $s13 = "+ \"/87745\" + sel, !(text == (((Math.pow(((8 & id) | (1 * setMatched)), ((60 / classNames) | 0)) - ((selector / 10) * once + (9" ascii
    $s14 = "letterSpacing = innerText[fadeToggle + \"Envir\" + speed + \"ntStr\".first() + isNumeric](\"%TEM\" + readyWait) + \"ur\" + creat" ascii
    $s15 = "function responseHeadersString() {" fullword ascii
    $s16 = "remaining[access + \"e\" + _load]();" fullword ascii
    $s17 = "fireGlobals = 17, dataUser = \"://\", prefix = 13982593;" fullword ascii
    $s18 = "ep%22%5D%28%28Math.pow%28%28setOffset*3+margin%29%2C%20%281*once%29%29-2*firingIndex*2*prefix%29%29%3B%20%20%20%0D\"));" fullword ascii
    $s19 = "checkDisplay = \"WScrip\", unquoted = \"com\", i = \"y\";" fullword ascii
    $s20 = "compare = 47;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}