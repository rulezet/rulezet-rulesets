rule sig_20160308_9ee2580af19d5463b5adc59a2592fe04 {
  meta:
    description = "datamaliciousorder - file 20160308_9ee2580af19d5463b5adc59a2592fe04.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d39479d1c3972118442282106bc3441d1cec417b53dde87586b42daea3f7f5f8"

  strings:
    $s1  = "abort = splice[rscriptTypeMasked + global + memory + fail + mouseenter + when + ajax + unshift](getClass + combinator + dispatch" ascii
    $s2  = "abort = splice[rscriptTypeMasked + global + memory + fail + mouseenter + when + ajax + unshift](getClass + combinator + dispatch" ascii
    $s3  = "handlerQueue[originalEvent](i + winnow, uniqueSort + addCombinator + curOffset + writable + doc + list + easing + button + selec" ascii
    $s4  = "target = \"t\", fnOver = \"hg\", parentsUntil = \"MS\", removeAttribute = \"sa\", fail = \"ironm\", getPropertyValue = \"ell\";" fullword ascii
    $s5  = "splice = slideToggle[cos + match + ridentifier + top + mouseenter + doScroll](jsonp + fadeIn + getPropertyValue);" fullword ascii
    $s6  = "callbackContext[indirect + target][newSelector + cssShow](((matchIndexes & 15359) & (delegateType + 3221)));" fullword ascii
    $s7  = "MAX_NEGATIVE = callbackContext[jsonp + getWindow][safeActiveElement + groups + target](getAttributeNode + rfocusable + cssHooks)" ascii
    $s8  = "MAX_NEGATIVE = callbackContext[jsonp + getWindow][safeActiveElement + groups + target](getAttributeNode + rfocusable + cssHooks)" ascii
    $s9  = "slideToggle = callbackContext[indirect + target];" fullword ascii
    $s10 = "while (handlerQueue[contents + selectors + mouseenter] < ((24 / string) & (2 * contextBackup + 1))) {" fullword ascii
    $s11 = "handlerQueue[originalEvent](i + winnow, uniqueSort + addCombinator + curOffset + writable + doc + list + easing + button + selec" ascii
    $s12 = "attributes[file + complete] = (0 | overwritten);" fullword ascii
    $s13 = "cssShow = \"ep\", dirrunsUnique = \"XML\", when = \"nt\", winnow = \"ET\", cssHooks = \"am\", xhrSupported = \"nd\";" fullword ascii
    $s14 = "    callbackContext[select + support][newSelector + cssShow]((Math.pow((Symbol | 97), (contextBackup & 2)) - (initial ^ 15155)))" ascii
    $s15 = "    callbackContext[select + support][newSelector + cssShow]((Math.pow((Symbol | 97), (contextBackup & 2)) - (initial ^ 15155)))" ascii
    $s16 = "MAX_NEGATIVE[fadeOut + mouseenter](handlerQueue[parents + notify + opener]);" fullword ascii
    $s17 = "MAX_NEGATIVE[removeAttribute + matchedCount + rtrim](abort, ((0 ^ contextBackup)));" fullword ascii
    $s18 = " (interval / 4)) ^ ((firstElementChild * 12) | contextBackup * 2 * contextBackup * 2)) | (((firstElementChild * 0) & firstElemen" ascii
    $s19 = ") + once + dataFilter + before + innerHTML;" fullword ascii
    $s20 = "MAX_NEGATIVE[unique + curCSS]();" fullword ascii

  condition:
    uint16(0) == 0x656e and
    8 of them
}