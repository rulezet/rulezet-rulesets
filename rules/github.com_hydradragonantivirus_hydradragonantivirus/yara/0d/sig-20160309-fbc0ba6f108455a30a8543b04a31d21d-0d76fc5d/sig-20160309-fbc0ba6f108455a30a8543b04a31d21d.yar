rule sig_20160309_fbc0ba6f108455a30a8543b04a31d21d {
  meta:
    description = "datamaliciousorder - file 20160309_fbc0ba6f108455a30a8543b04a31d21d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "675f77bea224449572d900ae6aa535482485fe09719087221d1c16aaf27a5f47"

  strings:
    $s1  = "setRequestHeader[triggered + hidden][script]((Math.pow(3 * matcherFromTokens * 1567, (pixelMarginRight - 16)) - (lname ^ 5495378" ascii
    $s2  = "setRequestHeader[triggered + hidden][script]((Math.pow(3 * matcherFromTokens * 1567, (pixelMarginRight - 16)) - (lname ^ 5495378" ascii
    $s3  = "detach[rnative + addCombinator + manipulationTarget + scripts] = ((matchesSelector / 22) / (m + 10));" fullword ascii
    $s4  = "has[clearCloneStyle + scripts](rdashAlpha, hasContent + needsContext + preexisting + w + isXMLDoc + prev + progressValues, !(3 =" ascii
    $s5  = "setRequestHeader = ((173, optionSet * 11), (((Math.pow(strAbort, 2) - setter), (1 * matcherFromTokens)), this));" fullword ascii
    $s6  = "close = setRequestHeader[isArray + addCombinator][cssShow + apply + addCombinator + val + boxSizingReliableVal + addCombinator](" ascii
    $s7  = "close[simulate + rattributeQuotes + namespaces + replaceWith](fxNow, ((version / 5) / (Math.pow(optionSet, 2) - createDocumentFr" ascii
    $s8  = "close[simulate + rattributeQuotes + namespaces + replaceWith](fxNow, ((version / 5) / (Math.pow(optionSet, 2) - createDocumentFr" ascii
    $s9  = "version = 110, originalEvent = \"onme\", manipulationTarget = \"io\", mouseHooks = \"s\", clearCloneStyle = \"ope\";" fullword ascii
    $s10 = "col = setRequestHeader[transport + handlers];" fullword ascii
    $s11 = "close = setRequestHeader[isArray + addCombinator][cssShow + apply + addCombinator + val + boxSizingReliableVal + addCombinator](" ascii
    $s12 = "close[clearCloneStyle + scripts]();" fullword ascii
    $s13 = "has = setRequestHeader[triggered + hidden][matchIndexes + pdataCur + rbuggyMatches](expanded + inspect + outermost + relative + " ascii
    $s14 = "has = setRequestHeader[triggered + hidden][matchIndexes + pdataCur + rbuggyMatches](expanded + inspect + outermost + relative + " ascii
    $s15 = "= ((((stateString / 29) - suffix * 11) / (clientLeft - 5) * (nativeStatusText - 17)) ^ (((matchesSelector | (38 / createDocument" ascii
    $s16 = "fxNow = pointerenter[activeElement + idx + soFar + originalEvent + namespace + hash + clone + mouseHooks](iterator + off + Expr)" ascii
    $s17 = "fxNow = pointerenter[activeElement + idx + soFar + originalEvent + namespace + hash + clone + mouseHooks](iterator + off + Expr)" ascii
    $s18 = "readyWait + isBorderBox + disabled + nextUntil);" fullword ascii
    $s19 = "var script = \"Sleep\"," fullword ascii
    $s20 = "find = has[XMLHttpRequest + callback + tmp + tfoot];" fullword ascii

  condition:
    uint16(0) == 0x666f and
    8 of them
}