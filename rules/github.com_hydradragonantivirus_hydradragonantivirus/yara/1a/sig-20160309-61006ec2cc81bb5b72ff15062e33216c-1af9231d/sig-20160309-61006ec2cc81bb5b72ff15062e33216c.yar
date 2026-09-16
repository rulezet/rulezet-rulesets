rule sig_20160309_61006ec2cc81bb5b72ff15062e33216c {
  meta:
    description = "datamaliciousorder - file 20160309_61006ec2cc81bb5b72ff15062e33216c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93b855de92ae8b973565b6335a6e857ac3dd1b4e1ada566d4013be6d0a6aa3a7"

  strings:
    $x1  = "dataUser[msg](rnamespace, charCode + msFullscreenElement + merge + boxSizingReliableVal + disableScript + dirruns + attrHandle +" ascii
    $s2  = "dataUser = setMatchers[compareDocumentPosition + relatedTarget][opt + rmouseEvent + condense](originalSettings + getElementById " ascii
    $s3  = "dataUser = setMatchers[compareDocumentPosition + relatedTarget][opt + rmouseEvent + condense](originalSettings + getElementById " ascii
    $s4  = "dataUser[msg](rnamespace, charCode + msFullscreenElement + merge + boxSizingReliableVal + disableScript + dirruns + attrHandle +" ascii
    $s5  = "dataAttr[source + rcomma] = ((node - 34) + (realStringObj / 13));" fullword ascii
    $s6  = "_queueHooks = setMatchers[isPropagationStopped + inspectPrefiltersOrTransports + source][setter + genFx + rmouseEvent + condense" ascii
    $s7  = "(5 * preDispatch)))), ((((3 + emptyStyle) + (4 | rquery)) & (Math.pow((11 | realStringObj), (1 + rquery)) - 2 * emptyStyle * 3 *" ascii
    $s8  = "setMatchers = (((5 + parseOnly) ^ 61 * emptyStyle), (((7 & val) + (40 - fragment)), this));" fullword ascii
    $s9  = "](guid + contentType + curLeft + tmp + classes);" fullword ascii
    $s10 = "_queueHooks = setMatchers[isPropagationStopped + inspectPrefiltersOrTransports + source][setter + genFx + rmouseEvent + condense" ascii
    $s11 = " parseOnly * 3)) + (((keys * 15 + emptyStyle) | (126, createHTMLDocument)) / ((7 * preDispatch + 1) & (checkDisplay + 2)))), (((" ascii
    $s12 = "firstChild = dataUser[matcher + sel];" fullword ascii
    $s13 = "visibility = setMatchers[compareDocumentPosition + hover + cssFn];" fullword ascii
    $s14 = "attrNames = second[removeChild + params + scrollTop + oldfire + flatOptions + isArrayLike + source + types + bind](inspect + sel" ascii
    $s15 = "second = visibility[keyCode + setDocument + funcName](originalProperties + defaultExtra + conditionFn);" fullword ascii
    $s16 = "selector = \"TEMP%\";" fullword ascii
    $s17 = "attrNames = second[removeChild + params + scrollTop + oldfire + flatOptions + isArrayLike + source + types + bind](inspect + sel" ascii
    $s18 = "charCode = \"http:/\", preDispatch = 4, guaranteedUnique = \"ep\", tmp = \"Strea\", nextUntil = \"ipt\";" fullword ascii
    $s19 = "getElementsByName = \"on\", hover = \"cri\", bubbleType = \"Sle\", node = 35, genFx = \"reate\", val = 7;" fullword ascii
    $s20 = "ector + els) + noop + stateVal + fx;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}