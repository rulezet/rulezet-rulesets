rule sig_20160308_c0c6645054a84a7193c0c38a16303ec6 {
  meta:
    description = "datamaliciousorder - file 20160308_c0c6645054a84a7193c0c38a16303ec6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3140b8ad7b7ebb83d497a8254f370a27ef4201641690b424d4293da0b321c48e"

  strings:
    $s1  = "removeProp[register + stopOnFalse](markFunction + end, splice + view + id + rnumnonpx + manipulationTarget + rts + elementMatche" ascii
    $s2  = "locked[win](has.compile(), ((1 + -attrHooks) ^ (0 / htmlPrefilter)), (0 | (postSelector / 21)));" fullword ascii
    $s3  = "attrHooks | 7)))) - ((((hasScripts - 36) & (adown | 7)) * ((postSelector | 2) ^ attrHooks) + (0 ^ docElem)) & (((57 - origCount)" ascii
    $s4  = "fix = \"TP\", isBorderBox = \"Run\", eventDoc = \"bject\", doc = \"TEMP%/\", serializeArray = \"Fil\", ready = \".scr\";" fullword ascii
    $s5  = "keyCode = (((235, wrapInner, 276) - (handleObjIn / 41)), (((errorCallback, 172, getElementsByName) ^ (5 * closest + 3)), this));" ascii
    $s6  = "rs, !((((((attrHooks * 1) + -attrHooks) | (0 ^ (attrHooks * 6))) + (((newCache / 30) + (postSelector | 8)) ^ ((forward - 55) + (" ascii
    $s7  = "removeProp[register + stopOnFalse](markFunction + end, splice + view + id + rnumnonpx + manipulationTarget + rts + elementMatche" ascii
    $s8  = "replaceWith = keyCode[extend + cloneCopyEvent][version + stopped + eventDoc](next + isPropagationStopped + matchesSelector + sty" ascii
    $s9  = "replaceWith = keyCode[extend + cloneCopyEvent][version + stopped + eventDoc](next + isPropagationStopped + matchesSelector + sty" ascii
    $s10 = "keyCode[msMatchesSelector + disabled][push + setAttribute](((statusCode / 11) & (Math.pow(fire, 2) - rescape)));" fullword ascii
    $s11 = "xhrSuccessStatus[properties + register + isFunction + fadeToggle] = (0 | postSelector);" fullword ascii
    $s12 = "getElementsByName = 12, file = \"ystate\", stopImmediatePropagation = \"typ\", src = \"writ\", iterator = \"read\";" fullword ascii
    $s13 = "removeProp = keyCode[msMatchesSelector + pointerleave + open][newDefer + rxhtmlTag + once + preferredDoc](throws + clientX + gen" ascii
    $s14 = "al + doc) + to + wrapAll + ajaxHandleResponses + ready;" fullword ascii
    $s15 = "removeProp = keyCode[msMatchesSelector + pointerleave + open][newDefer + rxhtmlTag + once + preferredDoc](throws + clientX + gen" ascii
    $s16 = "keyCode[disconnectedMatch + appendChild + raw][xhrFields](((26971 - isLocal) - (602 ^ firing)));" fullword ascii
    $s17 = "extend = (function Object.prototype.compile() {" fullword ascii
    $s18 = "selector = keyCode[disconnectedMatch + appendChild + raw];" fullword ascii
    $s19 = "has = progress[rinputs + not + image + setMatcher + matchesSelector + rattributeQuotes + JSON + pixelPosition](pixelMarginRightV" ascii
    $s20 = "test = \"Shell\";" fullword ascii

  condition:
    uint16(0) == 0x6966 and
    8 of them
}