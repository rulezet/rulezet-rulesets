rule sig_20160328_55afa0c036d1eab4bc89ab3e6b40dace {
  meta:
    description = "datamaliciousorder - file 20160328_55afa0c036d1eab4bc89ab3e6b40dace.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd730ff39a05f0a4af48212296698668f07fb2ae7473207d4ae186cf4fa42237"

  strings:
    $s1  = "rprotocol(currentTarget, currentTarget, stopped);" fullword ascii
    $s2  = "function appendTo(getElementsByTagName) {" fullword ascii
    $s3  = "   while(inPage[updateFunc + \"tat\" + stopped] != ((4 | disableScript))) mapped[\"WScrip\" + nodeName][\"Sleep\"](((301 & inner" ascii
    $s4  = "function nid(keepData, swap, get) {" fullword ascii
    $s5  = "   while(inPage[updateFunc + \"tat\" + stopped] != ((4 | disableScript))) mapped[\"WScrip\" + nodeName][\"Sleep\"](((301 & inner" ascii
    $s6  = "function $(tokenize) {" fullword ascii
    $s7  = "function list(hash) {" fullword ascii
    $s8  = "   if(inPage[letterSpacing] == ((69, jQuery) * 2 * (compilerCache + 0) * (splice, 5) * (username / 22))) {" fullword ascii
    $s9  = "function cssNumber() {" fullword ascii
    $s10 = "function rcheckableType() {" fullword ascii
    $s11 = "function delay() {" fullword ascii
    $s12 = "list(setMatchers);" fullword ascii
    $s13 = "function trim() {" fullword ascii
    $s14 = "function rprotocol(isArrayLike, noop, pixelMarginRightVal) {" fullword ascii
    $s15 = "delay(unqueued, delegateCount, letterSpacing);" fullword ascii
    $s16 = "function set(clientLeft, global) {" fullword ascii
    $s17 = "      ajaxExtend[prevAll + \"ript\"][done + \"p\"](((unique), (123, val)));" fullword ascii
    $s18 = "         trim(booleans, onerror, isPlainObject, gotoEnd, rbracket);" fullword ascii
    $s19 = "         set(unique, support, focusin, addToPrefiltersOrTransports);" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}