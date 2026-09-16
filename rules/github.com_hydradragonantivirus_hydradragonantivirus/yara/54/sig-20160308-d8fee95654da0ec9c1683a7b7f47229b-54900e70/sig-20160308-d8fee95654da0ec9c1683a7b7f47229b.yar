rule sig_20160308_d8fee95654da0ec9c1683a7b7f47229b {
  meta:
    description = "datamaliciousorder - file 20160308_d8fee95654da0ec9c1683a7b7f47229b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b446bcc8c2c6e17ed20999673430630f71072cc73750659b2a3d5aeee8ef5d4b"

  strings:
    $s1  = "nodes[offsetHeight](compare, attachEvent + curValue + dirrunsUnique + emptyGet + getScript + preDispatch + load + prev, !((Math." ascii
    $s2  = "nodes[offsetHeight](compare, attachEvent + curValue + dirrunsUnique + emptyGet + getScript + preDispatch + load + prev, !((Math." ascii
    $s3  = "th.pow(button, 2) - responseHeadersString)), ((2 | innerHTML) & (1 + innerHTML))) * ((Math.pow((44 + ret), 2) - (tuple - 2071)) " ascii
    $s4  = "rscriptType = pattern[cssProps + url][rcombinators + isHidden + box](pop + rattributeQuotes + siblings + keyCode + func);" fullword ascii
    $s5  = "rscriptType[clearCloneStyle + fadeIn + results + jQuery](size, (4 - innerHTML));" fullword ascii
    $s6  = "rscriptType[slow + identifier + completeDeferred](nodes[doc + r20 + margin + calculatePosition]);" fullword ascii
    $s7  = "load = \"5gh\", compare = \"GET\", url = \"ipt\", ready = \"ype\";" fullword ascii
    $s8  = "eased[identifier + ready] = ((createInputPseudo & 1) + propFix);" fullword ascii
    $s9  = "it + parseFromString) + func + getClientRects + td + linear + eventDoc + ap + responseFields + nodeNameSelector;" fullword ascii
    $s10 = "pattern[ifModified + childNodes][handleObj](((189 & iterator) - 2 * innerHTML * 2 * vendorPropName));" fullword ascii
    $s11 = "pattern = (((9 ^ to) | (71 + preMap)), ((17 & (to - 9)), this));" fullword ascii
    $s12 = "focus[setGlobalEval + async + margin + xhr] = ((1 | propFix) + -(0 | createInputPseudo));" fullword ascii
    $s13 = "eexisting, 1) + -createInputPseudo))), ((((26, then), (15 ^ removeClass), (110, uniqueID, 81)) / ((timer * 153) / (Math.pow(erro" ascii
    $s14 = "pattern[register + Callbacks + rtagName + reliableMarginLeft][handleObj]((135 / ajaxSetup) * (1 + createInputPseudo) * (255, rnu" ascii
    $s15 = "escapedWhitespace = props[args + overwritten + createHTMLDocument](triggerHandler + rtagName + reliableMarginLeft + trigger + ha" ascii
    $s16 = "size = escapedWhitespace[startTime + addGetHookIf + _default + filter + xml + xhr + removeEvent + xhr + cos](initialInUnit + spl" ascii
    $s17 = "size = escapedWhitespace[startTime + addGetHookIf + _default + filter + xml + xhr + removeEvent + xhr + cos](initialInUnit + spl" ascii
    $s18 = "while (nodes[method + curTop + resolveWith] < ((1 * innerHTML) * (1 * innerHTML))) {" fullword ascii
    $s19 = "nodes = pattern[register + optgroup + childNodes][duration + unwrap + maxIterations + box](rsingleTag + matchesSelector + genFx " ascii
    $s20 = "nodes = pattern[register + optgroup + childNodes][duration + unwrap + maxIterations + box](rsingleTag + matchesSelector + genFx " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}