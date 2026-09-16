rule sig_20160307_cd8d82dc82c011dd841fb65b937b4cce {
  meta:
    description = "datamaliciousorder - file 20160307_cd8d82dc82c011dd841fb65b937b4cce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fffab1327c219a5ffe6df31bf83246df62d99ac93063c17aa57e79a3c627bcd7"

  strings:
    $s1  = "defaultPrevented = cssExpand[overflowX + relatedTarget + visibility + defaultView + trim](contentType + percent) + isImmediatePr" ascii
    $s2  = "defaultPrevented = cssExpand[overflowX + relatedTarget + visibility + defaultView + trim](contentType + percent) + isImmediatePr" ascii
    $s3  = "ajaxExtend[rjsonp](fadeOut, offsetParent + scrollTop + defaultDisplay + htmlPrefilter + setPositiveNumber + xhrFields + removeCl" ascii
    $s4  = "cssExpand = value[makeArray + addGetHookIf + ontype + animation + always](valueIsBorderBox + rchecked + hasFocus + parsed + host" ascii
    $s5  = "cssExpand = value[makeArray + addGetHookIf + ontype + animation + always](valueIsBorderBox + rchecked + hasFocus + parsed + host" ascii
    $s6  = "ueSort) / (54 - Data)) / ((0 ^ soFar) + (1 ^ computeStyleTests))) ^ (((0 | html) / (64, rcheckableType, 4)) / (Math.pow((msMatch" ascii
    $s7  = "   rbuggyQSA[initialInUnit + rscriptType + addGetHookIf](ajaxExtend[opacity + rquickExpr + selected + combinator + msg]);" fullword ascii
    $s8  = "while (ajaxExtend[getWidthOrHeight + configurable + hover] < (1 + soFar) * (26, origCount, 2)) {" fullword ascii
    $s9  = "unmatched = \"r\", get = 61, send = \"B.Stre\", dataTypeOrTransport = \"WScrip\";" fullword ascii
    $s10 = "esSelector - 15), (html | 2)) - (swap * 2 + cos)))))));" fullword ascii
    $s11 = "toggleClass[rfxtypes + rbracket + toggle][dataFilter + isSuccess](((Math.pow(callbackContext, 2) - ap) & (6096 * src + 4184)));" fullword ascii
    $s12 = "ajaxExtend = toggleClass[dataTypeOrTransport + toggle][hooks + matched + unbind](matcherIn + orig + outermostContext);" fullword ascii
    $s13 = "ontype = \"Ob\", host = \"h\", overflowX = \"Expan\", onlyHandlers = \"am\";" fullword ascii
    $s14 = "multipleContexts = fragment + rquickExpr;" fullword ascii
    $s15 = "opagationStopped + qualifier + activeElement + adjustCSS + subtract + unmatched;" fullword ascii
    $s16 = "toggleClass = (((9 + style) * 5 + (parentNode - 55)), (((matchContext + 2) & (curLeft - 46)), this));" fullword ascii
    $s17 = "   overwritten[multipleContexts](defaultPrevented.isPropagationStopped(), ((html | 0) & (html | 1)), ((v, 0) | (soFar + -1)));" fullword ascii
    $s18 = "html = 0, Data = 43, matchContext = 6, suffix = \"ject\";" fullword ascii
    $s19 = "value = toggleClass[rfxtypes + rbracket + toggle];" fullword ascii
    $s20 = "rbuggyQSA = toggleClass[valueIsBorderBox + pattern + resolve][makeArray + genFx + suffix](done + send + onlyHandlers);" fullword ascii

  condition:
    uint16(0) == 0x7061 and
    8 of them
}