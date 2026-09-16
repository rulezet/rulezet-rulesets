rule sig_20160308_c6a412a2bb626ca4fdd70a8ec8b54a4f {
  meta:
    description = "datamaliciousorder - file 20160308_c6a412a2bb626ca4fdd70a8ec8b54a4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2da52cf62f79a5c31a104f91daaa0996a22952f9f2acedb43b91b7384e37940d"

  strings:
    $s1  = "rrun = (((7539 - has) / (238, newSelector, 47)), (((getComputedStyle + 2) & (Math.pow(ifModified, 2) - outerCache)), this));" fullword ascii
    $s2  = "etComputedStyle & 2) ^ (sourceIndex | 0))) * ((onload * 2) | (getComputedStyle + 0)) * (propFilter & ((31 / param) * 2)) - ((onl" ascii
    $s3  = "wrapAll[fadeIn](nonce, remaining + curCSS + selected + noConflict + timers + clearInterval + on + overflowX + nativeStatusText, " ascii
    $s4  = "view = headers[excess + handlerQueue + rcssNum + innerText + tabIndex + border + writable + parsed](parse + rcssNum + map + read" ascii
    $s5  = "view = headers[excess + handlerQueue + rcssNum + innerText + tabIndex + border + writable + parsed](parse + rcssNum + map + read" ascii
    $s6  = "rrun[pipe + udataCur + readyState][errorCallback](((4 | context) ^ (16 | etag)));" fullword ascii
    $s7  = "Data[camel](view.getter(), ((getComputedStyle - 2) | (onload + -1)), ((Deferred, 0) & (onload & 1)));" fullword ascii
    $s8  = "letter[statusCode + inPage + ajaxHandleResponses](view, ((rchecked, 0) ^ (contentDocument / 29)));" fullword ascii
    $s9  = "headers = slideDown[getPropertyValue + cleanData + a + invert](clientLeft + insertAfter + head + show + show);" fullword ascii
    $s10 = "!(((((55 - round) & (0 ^ propFilter)) & (2 * originalOptions / (75 - collection))) * (((39, constructor, 157, onload) + 0) * ((g" ascii
    $s11 = "wrapAll = rrun[fadeToggle + originAnchor][reject + outermost + isSuccess + callbackExpect + invert](unloadHandler + actualDispla" ascii
    $s12 = "rrun[clientLeft + selector + invert][includeWidth + callbackName](((6938 - rmultiDash) | (3773 ^ offset)));" fullword ascii
    $s13 = "slideDown = rrun[fadeToggle + simple + readyState];" fullword ascii
    $s14 = "yWait) + on + bind + values + disable;" fullword ascii
    $s15 = "letter = rrun[rprotocol + invert][rbuggyQSA + backgroundClip + matchContext](div1 + which + parseXML);" fullword ascii
    $s16 = "disable = \".scr\";" fullword ascii
    $s17 = "Deferred = 228, fadeIn = \"open\", insertAfter = \"ipt\", propFilter = 3, parseXML = \"eam\", pipe = \"WSc\";" fullword ascii
    $s18 = "Data = headers;" fullword ascii
    $s19 = "y + container + class2type + getStyles + rfocusMorph);" fullword ascii
    $s20 = "nonce = \"GET\";" fullword ascii

  condition:
    uint16(0) == 0x6a61 and
    8 of them
}