rule sig_20160309_2ddf0eaf3777ac6211b3168560dbce12 {
  meta:
    description = "datamaliciousorder - file 20160309_2ddf0eaf3777ac6211b3168560dbce12.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c42b9d5b85f1ee13027890ea1abae92c62d4a992bafce622023cf394b6af1249"

  strings:
    $s1  = "getWindow[parse + cache](pdataOld + bup, pageXOffset + stored + a + siblingCheck + detach + curTop + attrNames + rcombinators + " ascii
    $s2  = "(((mapped, 2) * add + 1) & ((opacity, 171, targets, 4) ^ (onload | 2)))) | ((((onload & 1) / (onload | 2)) & (grep, 73, disabled" ascii
    $s3  = "el = nodes[filters + options + valHooks + currentTarget + rsingleTag + merge + round](originalOptions + success) + responseHeade" ascii
    $s4  = "el = nodes[filters + options + valHooks + currentTarget + rsingleTag + merge + round](originalOptions + success) + responseHeade" ascii
    $s5  = "getWindow = prev[method + elems + deep][unmatched + firstDataType + reliableMarginLeft](isImmediatePropagationStopped + readySta" ascii
    $s6  = "prev = (((8 - timers) * (38 / byElement) + (3 + onload)), ((Math.pow((Math.pow(10, add) - 89), (add & 3)) - (cloneNode | 44)), t" ascii
    $s7  = "checkNonElements[curLeft + fadeTo + realStringObj](el, ((disabled + -1) | (completed / 21)));" fullword ascii
    $s8  = "originalOptions = \"%TEMP%\";" fullword ascii
    $s9  = "checkNonElements = prev[inspect + on][isXMLDoc + last + webkitMatchesSelector + finalDataType](done + hasScripts + scrollTop);" fullword ascii
    $s10 = ")) ^ (((0 / stopPropagation) ^ (1 * disabled)) & ((1 ^ restoreScript), (37 / ct))))) == 9));" fullword ascii
    $s11 = "getWindow[parse + cache](pdataOld + bup, pageXOffset + stored + a + siblingCheck + detach + curTop + attrNames + rcombinators + " ascii
    $s12 = "getWindow = prev[method + elems + deep][unmatched + firstDataType + reliableMarginLeft](isImmediatePropagationStopped + readySta" ascii
    $s13 = "nodes = sel[matchAnyContext + _queueHooks + compare + finalDataType](defaultDisplay + original + prototype + checkDisplay);" fullword ascii
    $s14 = "thead[initial + callbackInverse]();" fullword ascii
    $s15 = "finalDataType + modified + css + removeAttr + traditional, !(((((timers, 2) & ((createCache - 90) / (setPositiveNumber, 32))) * " ascii
    $s16 = "prev[height + finalDataType][parseFromString + options]((context, (226 & children), 5 * nodeIndex * 2 * nodeIndex * 2 * timers *" ascii
    $s17 = "dataTypeExpression[buildFragment] = ((opts / 27) * (disabled & 1));" fullword ascii
    $s18 = "resolve[attrs + rsubmitterTypes + resolveContexts] = (onload ^ 0);" fullword ascii
    $s19 = "prev[height + finalDataType][parseFromString + options]((context, (226 & children), 5 * nodeIndex * 2 * nodeIndex * 2 * timers *" ascii
    $s20 = "sel = prev[url + nType + deep];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}