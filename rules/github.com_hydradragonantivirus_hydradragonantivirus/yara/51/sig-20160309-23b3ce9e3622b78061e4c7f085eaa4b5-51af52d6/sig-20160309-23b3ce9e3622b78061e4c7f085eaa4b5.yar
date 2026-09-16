rule sig_20160309_23b3ce9e3622b78061e4c7f085eaa4b5 {
  meta:
    description = "datamaliciousorder - file 20160309_23b3ce9e3622b78061e4c7f085eaa4b5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0b043f2a2a38c862a3c2f3e7273d273324f644a86379c9fef1b053bdfc95ba2"

  strings:
    $x1  = "noGlobal[compareDocumentPosition](content + curOffset, n + rtrim + caption + width + excess + holdReady + parseOnly + m, !(inner" ascii
    $s2  = "reliableMarginRight[pointerenter + focus + noop + closest][thead + finalDataType + serialize](pointerleave * (5 & attachEvent) *" ascii
    $s3  = "nTarget)) + (((1020 - interval) / (1 + jsonpCallback)) / (1 * tbody) * (68 / prevAll))))));" fullword ascii
    $s4  = "Text == (((((1 + nType) ^ (39 - rbuggyQSA)) ^ ((221, removeProp, 115, restoreScript) & (91 - div))) & (((1 * nType) | (828 / hig" ascii
    $s5  = "ajaxSettings = prop[diff + scrollLeft + head + getResponseHeader + tabIndex + resolveWith + rxhtmlTag + contentType + location](" ascii
    $s6  = "ajaxSettings = prop[diff + scrollLeft + head + getResponseHeader + tabIndex + resolveWith + rxhtmlTag + contentType + location](" ascii
    $s7  = "fontWeight[_data + key + register + linear](requestHeaders);" fullword ascii
    $s8  = "noGlobal[compareDocumentPosition](content + curOffset, n + rtrim + caption + width + excess + holdReady + parseOnly + m, !(inner" ascii
    $s9  = "eContainer + thead + before + getJSON);" fullword ascii
    $s10 = "reliableMarginRight[pointerenter + focus + noop + closest][thead + finalDataType + serialize](pointerleave * (5 & attachEvent) *" ascii
    $s11 = "fontWeight = reliableMarginRight[pointerenter + boxSizingReliable + rxhtmlTag][setup + getAll + pixelPositionVal + opts](respons" ascii
    $s12 = "fontWeight = reliableMarginRight[pointerenter + boxSizingReliable + rxhtmlTag][setup + getAll + pixelPositionVal + opts](respons" ascii
    $s13 = "h)) ^ ((31 - getAllResponseHeaders) | (45 - test)))) - ((((436 - cacheLength) | (8 ^ nType)) / (118, curCSSTop, 255, manipulatio" ascii
    $s14 = "styles + getBoundingClientRect) + superMatcher + relative + getJSON + origType + focus;" fullword ascii
    $s15 = "escapedWhitespace[dest] = ((17 + source), (21 & hasContent), 29, completeDeferred);" fullword ascii
    $s16 = "matchesSelector = \"eToF\", restoreScript = 17, num = \"ct\", contentType = (function Object.prototype.fcamelCase() {" fullword ascii
    $s17 = "noGlobal[combinator + setMatcher]();" fullword ascii
    $s18 = "content = \"G\";" fullword ascii
    $s19 = "requestHeaders = noGlobal[oldCache + container + anim + box + ifModified];" fullword ascii
    $s20 = "head = \"pandE\"," fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}