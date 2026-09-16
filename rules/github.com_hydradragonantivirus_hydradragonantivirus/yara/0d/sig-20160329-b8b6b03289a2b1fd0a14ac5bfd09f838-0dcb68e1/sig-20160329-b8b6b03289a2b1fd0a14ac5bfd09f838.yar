rule sig_20160329_b8b6b03289a2b1fd0a14ac5bfd09f838 {
  meta:
    description = "datamaliciousorder - file 20160329_b8b6b03289a2b1fd0a14ac5bfd09f838.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db27c3b4ba4215b6281a8285b20e42f1b50decb015c2d0ce5dfc4d1b3afe8395"

  strings:
    $s1  = "function getStyles(compile, defaultExtra) {" fullword ascii
    $s2  = "rootjQuery[rtrim + \"yp\" + resolve] = 1;" fullword ascii
    $s3  = "    if (matcherOut[inspect + \"atu\" + matcherIn] == (Math.pow((protocol & 139), (lastModified + 1)) - (onlyHandlers & 27313))) " ascii
    $s4  = "uid(responseHeaders, prefix, adjustCSS);" fullword ascii
    $s5  = "        rootjQuery[linear + \"File\"](disableScript, (curPosition / 36));" fullword ascii
    $s6  = "function addCombinator() {" fullword ascii
    $s7  = "childNodes(onlyHandlers, replaceChild, token);" fullword ascii
    $s8  = "            matcherOut[\"s\" + token + \"d\"]();" fullword ascii
    $s9  = "easing();" fullword ascii
    $s10 = "function udataOld() {" fullword ascii
    $s11 = "function childNodes() {" fullword ascii
    $s12 = "function appendChild(progress, clazz) {" fullword ascii
    $s13 = "function uid(type, resolveContexts) {" fullword ascii
    $s14 = "function curTop(has, isWindow) {" fullword ascii
    $s15 = "attr = updateFunc = argument = fixHooks = createHTMLDocument.soFar();" fullword ascii
    $s16 = "finish(hide, eventHandle, adjustCSS);" fullword ascii
    $s17 = "function preFilters(select) {" fullword ascii
    $s18 = "function prevUntil(col, removeEvent) {" fullword ascii
    $s19 = "function finish(urlAnchor, valueIsBorderBox) {" fullword ascii
    $s20 = "            isLocal(createDocumentFragment, head, curOffset, tick, p);" fullword ascii

  condition:
    uint16(0) == 0x736d and
    8 of them
}