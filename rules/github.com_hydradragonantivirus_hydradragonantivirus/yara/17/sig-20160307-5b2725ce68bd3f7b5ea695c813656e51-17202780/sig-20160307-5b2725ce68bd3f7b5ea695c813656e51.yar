rule sig_20160307_5b2725ce68bd3f7b5ea695c813656e51 {
  meta:
    description = "datamaliciousorder - file 20160307_5b2725ce68bd3f7b5ea695c813656e51.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3aace37fe96502b3dee288b55c97040d56234279f067de4b8ab25d4a7c75837"

  strings:
    $s1  = "targets[fast + keyHooks](crossDomain + setMatchers, notifyWith + promise + matched + dest + parts + reverse + attributes + store" ascii
    $s2  = "getStyles[token + groups][postMap + promise]((Math.pow((Math.pow(curTop, 2) - unique), 2) - (key * 2 + iNoClone)));" fullword ascii
    $s3  = "while(targets[get + disabled + groups + propName] < ((Math.pow(start, 2) - jQuery) & (Math.pow(3, nid) - 5))) {" fullword ascii
    $s4  = "targets = getStyles[originalOptions + stateString][height + parseJSON + set + linear + nodeName + cos](copyIsArray + rootjQuery " ascii
    $s5  = "targets = getStyles[originalOptions + stateString][height + parseJSON + set + linear + nodeName + cos](copyIsArray + rootjQuery " ascii
    $s6  = "targets[fast + keyHooks](crossDomain + setMatchers, notifyWith + promise + matched + dest + parts + reverse + attributes + store" ascii
    $s7  = "targets[createTextNode + propName + clientX + container]();" fullword ascii
    $s8  = "attributes = \".com.\", curCSS = 47, tokenize = 255, abort = 133, rpseudo = \"nseBo\";" fullword ascii
    $s9  = "d + newUnmatched + promise + curElem + hasContent + doneName, !((((((childNodes + 0) + -childNodes) ^ 0) | (((childNodes * 1) * " ascii
    $s10 = "random = getStyles[current + rchecked][rnoInnerhtml + tfoot](pointerleave + keyCode + parseJSON + bool);" fullword ascii
    $s11 = "   random[owner + risSimple](targets[outermost + rpseudo + dirruns]);" fullword ascii
    $s12 = "curCSSLeft = clientTop[constructor + raw + isHidden + match + siblings + isXML + doneName + border](implementation + arr) + read" ascii
    $s13 = "getStyles = ((251, nid * 3, nid * 2 * fireWith * 19), (((start + 0) ^ (matchAnyContext + 13)), this));" fullword ascii
    $s14 = "   addGetHookIf[getter] = ((95 - opts) - (27 & destElements));" fullword ascii
    $s15 = "clientTop = fireGlobals[origCount + isBorderBox + checkContext + whitespace](self + resolveContexts + groups + dirrunsUnique + p" ascii
    $s16 = "curCSSLeft = clientTop[constructor + raw + isHidden + match + siblings + isXML + doneName + border](implementation + arr) + read" ascii
    $s17 = "clientTop = fireGlobals[origCount + isBorderBox + checkContext + whitespace](self + resolveContexts + groups + dirrunsUnique + p" ascii
    $s18 = "toggle = \"po\", stateString = \"Script\", groups = \"t\";" fullword ascii
    $s19 = "current = \"WS\", jQuery = 9, postMap = \"Slee\";" fullword ascii
    $s20 = "getter = \"type\", raw = \"dE\", originalOptions = \"W\";" fullword ascii

  condition:
    uint16(0) == 0x7270 and
    8 of them
}