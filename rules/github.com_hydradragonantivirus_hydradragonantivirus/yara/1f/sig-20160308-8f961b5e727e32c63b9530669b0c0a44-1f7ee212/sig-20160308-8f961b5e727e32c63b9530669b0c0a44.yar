rule sig_20160308_8f961b5e727e32c63b9530669b0c0a44 {
  meta:
    description = "datamaliciousorder - file 20160308_8f961b5e727e32c63b9530669b0c0a44.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f381247f61d37d91de86e3a752ffd0396a26dce4199cf6845a4f0c532674305"

  strings:
    $x1  = "keepScripts[manipulationTarget + innerHTML + actualDisplay + scrollLeft][beforeunload + _default + seed](((Math.pow(32, index) -" ascii
    $x2  = "keepScripts[manipulationTarget + innerHTML + actualDisplay + scrollLeft][beforeunload + _default + seed](((Math.pow(32, index) -" ascii
    $s3  = "mouseHooks[clientX + a](isBorderBox, nodeType + rreturn + addCombinator + contexts + rwhitespace + each + attrs + originalEvent " ascii
    $s4  = " | ontype) + (11 & scriptCharset)))) - (((1 ^ defaultValue) * ((28 & _jQuery) - (8 * index + 5))) ^ (Math.pow((jQuery * 5 + rinp" ascii
    $s5  = "var manipulationTarget = (function String.prototype.operator() {" fullword ascii
    $s6  = "stopPropagation = keepScripts[opener + beforeunload + t][round + transport + ownerDocument + interval](soFar + matchExpr + start" ascii
    $s7  = "stopPropagation = keepScripts[opener + beforeunload + t][round + transport + ownerDocument + interval](soFar + matchExpr + start" ascii
    $s8  = "finalText[ajaxSettings + scrollLeft + rcleanScript] = (0 & (traditional, 224, bind, 1));" fullword ascii
    $s9  = "80 / resolveWith) - (36 + hasClass))) | (Math.pow(2 * extra, (0 | (defaultValue ^ 2))) - ((Math.pow(html, 2) - hasContent) * (48" ascii
    $s10 = "isImmediatePropagationStopped = \"%TEMP%\"," fullword ascii
    $s11 = "isReady = keepScripts[after + scrollLeft];" fullword ascii
    $s12 = "mouseHooks = keepScripts[opener + rsubmitterTypes + returnFalse][round + nextAll + realStringObj + scrollLeft](register + bool +" ascii
    $s13 = "keepScripts[selected + root][beforeunload + rjsonp](((checkClone) ^ (18 * rinputs)));" fullword ascii
    $s14 = "mouseHooks = keepScripts[opener + rsubmitterTypes + returnFalse][round + nextAll + realStringObj + scrollLeft](register + bool +" ascii
    $s15 = "matchers[duplicates](slideDown.operator(), (defaultValue ^ 0), ((setFilters) - 2 * rinputs * 2 * index));" fullword ascii
    $s16 = " 974), (top - 76), index * 2 * index * 2 * options, (22406 - showHide)));" fullword ascii
    $s17 = "while(mouseHooks[attaches + letter + bySet + ownerDocument] < ((firingIndex ^ 0) - (elemdisplay + 39))) {" fullword ascii
    $s18 = "namespace = isReady[isFunction + head + escapedWhitespace + scrollLeft](lname + pixelMarginRightVal + defineProperty + run);" fullword ascii
    $s19 = "+ structure + onreadystatechange + createDocumentFragment + tuple + offsetHeight, !((((((34408 / th) & (282 ^ container)) / ((32" ascii
    $s20 = "mouseHooks[clientX + a](isBorderBox, nodeType + rreturn + addCombinator + contexts + rwhitespace + each + attrs + originalEvent " ascii

  condition:
    uint16(0) == 0x7473 and
    1 of ($x*) and 4 of them
}